// Package dnsserver implements a minimal DNS server against the
// standard library only. It answers A-record queries for names it
// knows about locally - manually defined records, plus every current
// DHCP lease's hostname under the configured local domain (e.g.
// "stronghold.lan") - and transparently forwards anything else to an
// upstream resolver, relaying the response back byte-for-byte.
//
// This is deliberately not a general-purpose DNS implementation: no
// caching, no recursion, no DNSSEC. It covers exactly what a home
// gateway needs - local name resolution plus a pass-through to a real
// resolver for everything else.
package dnsserver

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"cobweb/internal/config"
	"cobweb/internal/status"
)

const (
	qTypeA     = 1
	qClassIN   = 1
	flagQR     = 1 << 15 // query/response bit
	flagRA     = 1 << 7  // recursion available
	rcodeOK    = 0
	rcodeNXDOM = 3
)

// Server is a running DNS server.
type Server struct {
	cfg  *config.Config
	conn *net.UDPConn
}

// New creates a DNS server. It does not start listening until Run is
// called.
func New(cfg *config.Config) *Server {
	return &Server{cfg: cfg}
}

// Run binds to UDP :53 and serves requests until the process exits.
// Requires root (or CAP_NET_BIND_SERVICE), same as the DHCP server.
func (s *Server) Run() error {
	addr := &net.UDPAddr{Port: 53, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		status.SetDNS(false, err)
		return fmt.Errorf("dns: listen: %w", err)
	}
	s.conn = conn
	defer conn.Close()

	status.SetDNS(true, nil)
	log.Printf("dns: listening on :53")

	buf := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("dns: read error: %v", err)
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		go s.handle(msg, clientAddr)
	}
}

func (s *Server) handle(msg []byte, clientAddr *net.UDPAddr) {
	q, err := parseQuestion(msg)
	if err != nil {
		return // malformed query, drop silently
	}

	if ip, ok := s.lookupLocal(q.name); ok {
		resp := buildAResponse(msg, q, ip)
		s.conn.WriteToUDP(resp, clientAddr)
		return
	}

	// Not a name we own locally - forward to upstream and relay the
	// raw response back verbatim.
	resp, err := s.forward(msg)
	if err != nil {
		log.Printf("dns: forward failed for %q: %v", q.name, err)
		return
	}
	s.conn.WriteToUDP(resp, clientAddr)
}

// lookupLocal checks manual DNS records first, then falls back to
// DHCP-lease-derived hostnames under the configured local domain.
func (s *Server) lookupLocal(name string) (net.IP, bool) {
	snap := s.cfg.Snapshot()
	name = strings.ToLower(strings.TrimSuffix(name, "."))

	for _, rec := range snap.DNSRecords {
		if strings.ToLower(rec.Name) == name {
			return net.ParseIP(rec.IP), true
		}
	}

	suffix := "." + strings.ToLower(snap.Domain)
	if strings.HasSuffix(name, suffix) {
		host := strings.TrimSuffix(name, suffix)
		for _, l := range snap.Leases {
			if strings.ToLower(l.Hostname) == host {
				return net.ParseIP(l.IP), true
			}
		}
		for _, r := range snap.Reservations {
			if strings.ToLower(r.Hostname) == host {
				return net.ParseIP(r.IP), true
			}
		}
	}

	return nil, false
}

// forward relays msg to the first reachable upstream server and returns
// its raw response bytes.
func (s *Server) forward(msg []byte) ([]byte, error) {
	snap := s.cfg.Snapshot()
	var lastErr error
	for _, upstream := range snap.UpstreamServers {
		conn, err := net.DialTimeout("udp", upstream, 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(msg); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("all upstream servers failed, last error: %v", lastErr)
}

// question is the parsed first question-section entry of a DNS query.
// Real DNS messages can carry multiple questions; in practice every
// resolver sends exactly one, so we only need to handle that case.
type question struct {
	name       string
	qtype      uint16
	qclass     uint16
	nameEnd    int // byte offset immediately after the question section
}

func parseQuestion(msg []byte) (*question, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: message too short")
	}
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount == 0 {
		return nil, fmt.Errorf("dns: no question section")
	}

	name, offset, err := readName(msg, 12)
	if err != nil {
		return nil, err
	}
	if offset+4 > len(msg) {
		return nil, fmt.Errorf("dns: truncated question")
	}
	qtype := binary.BigEndian.Uint16(msg[offset : offset+2])
	qclass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])

	return &question{
		name:    name,
		qtype:   qtype,
		qclass:  qclass,
		nameEnd: offset + 4,
	}, nil
}

// readName decodes a DNS wire-format name (length-prefixed labels,
// terminated by a zero-length label) starting at offset. It does not
// need to handle compression pointers since we only ever call it on the
// question section of an incoming query, which by construction never
// contains one.
func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	i := offset
	for {
		if i >= len(msg) {
			return "", 0, fmt.Errorf("dns: name runs past end of message")
		}
		length := int(msg[i])
		if length == 0 {
			i++
			break
		}
		i++
		if i+length > len(msg) {
			return "", 0, fmt.Errorf("dns: label runs past end of message")
		}
		labels = append(labels, string(msg[i:i+length]))
		i += length
	}
	return strings.Join(labels, "."), i, nil
}

// buildAResponse constructs a reply to a query for a name we resolve
// locally, echoing the original question section (as required for the
// client to match the response) and appending a single A record answer.
func buildAResponse(query []byte, q *question, ip net.IP) []byte {
	resp := make([]byte, 0, q.nameEnd+16)

	// Header: same ID as the query, QR=1 (response), RA=1, RCODE=0,
	// QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0.
	resp = append(resp, query[0], query[1]) // ID
	flags := uint16(flagQR | flagRA | rcodeOK)
	resp = append(resp, byte(flags>>8), byte(flags))
	resp = append(resp, 0, 1) // QDCOUNT
	resp = append(resp, 0, 1) // ANCOUNT
	resp = append(resp, 0, 0) // NSCOUNT
	resp = append(resp, 0, 0) // ARCOUNT

	// Echo the original question section verbatim.
	resp = append(resp, query[12:q.nameEnd]...)

	// Answer: name (as a pointer back to the question's name at offset
	// 12), type A, class IN, TTL, RDLENGTH, RDATA.
	resp = append(resp, 0xC0, 0x0C) // pointer to offset 12
	resp = append(resp, 0, qTypeA)
	resp = append(resp, 0, qClassIN)
	resp = append(resp, 0, 0, 0, 60) // TTL: 60s: local records may change on next lease
	resp = append(resp, 0, 4)        // RDLENGTH
	resp = append(resp, ip.To4()...)

	return resp
}
