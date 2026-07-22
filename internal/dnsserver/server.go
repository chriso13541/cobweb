// Package dnsserver implements a minimal DNS server against the
// standard library only. It answers A-record queries for names it
// knows about locally - manually defined records, plus every current
// DHCP lease's hostname under the configured local domain (e.g.
// "stronghold.lan") - and handles everything else one of two ways,
// per the configured DNSMode: "forward" relays queries to an upstream
// resolver (Cloudflare/Quad9 by default) byte-for-byte, while
// "recursive" resolves them itself by walking the real DNS delegation
// chain (root -> TLD -> authoritative servers), so no single upstream
// ever sees a full query history.
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
	cfg   *config.Config
	conn  *net.UDPConn
	cache *recursiveCache
}

// New creates a DNS server. It does not start listening until Run is
// called.
func New(cfg *config.Config) *Server {
	cache := newRecursiveCache()
	activeCache = cache
	return &Server{cfg: cfg, cache: cache}
}

// activeCache points at the currently running server's cache. There's
// only ever one dnsserver.Server per process in practice, so this is a
// simple way for the web dashboard to read cache effectiveness without
// needing a direct reference to the Server itself.
var activeCache *recursiveCache

// CacheStats returns the current DNS cache size and cumulative
// hit/miss counts, for the dashboard's performance panel. Safe to call
// even if recursive mode has never been used (returns all zeros).
func CacheStats() (entries, hits, misses int) {
	if activeCache == nil {
		return 0, 0, 0
	}
	return activeCache.stats()
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
		resp := buildAResponse(msg, q, []net.IP{ip}, 60)
		s.conn.WriteToUDP(resp, clientAddr)
		return
	}

	if s.cfg.Snapshot().DNSMode == "recursive" && q.qtype == qTypeA {
		s.handleRecursive(msg, q, clientAddr)
		return
	}

	// Forward mode (default), or a query type recursive mode doesn't
	// handle itself (only A records are resolved iteratively; anything
	// else still goes to upstream even in recursive mode).
	resp, err := s.forward(msg)
	if err != nil {
		log.Printf("dns: forward failed for %q: %v", q.name, err)
		return
	}
	s.conn.WriteToUDP(resp, clientAddr)
}

// handleRecursive answers a query by walking the real DNS delegation
// chain itself (see resolveIterative), checking the local cache first
// so repeat lookups don't pay the multi-hop cost every time.
func (s *Server) handleRecursive(msg []byte, q *question, clientAddr *net.UDPAddr) {
	cacheKey := strings.ToLower(q.name) + "|A"

	if ips, ok := s.cache.get(cacheKey); ok {
		resp := buildAResponse(msg, q, ips, 60)
		s.conn.WriteToUDP(resp, clientAddr)
		return
	}

	answer, err := resolveIterative(q.name, qTypeA)
	if err != nil {
		log.Printf("dns: recursive resolution failed for %q: %v", q.name, err)
		// Fall back to forwarding rather than leaving the client
		// hanging - a slow/unreachable root server shouldn't mean a
		// browsing session just breaks.
		resp, fwdErr := s.forward(msg)
		if fwdErr != nil {
			log.Printf("dns: fallback forward also failed for %q: %v", q.name, fwdErr)
			return
		}
		s.conn.WriteToUDP(resp, clientAddr)
		return
	}

	s.cache.set(cacheKey, answer.IPs, answer.TTL)
	resp := buildAResponse(msg, q, answer.IPs, answer.TTL)
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
	name    string
	qtype   uint16
	qclass  uint16
	nameEnd int // byte offset immediately after the question section
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

// buildAResponse constructs a reply to a resolved query, echoing the
// original question section (as required for the client to match the
// response) and appending one A record answer per IP in ips.
func buildAResponse(query []byte, q *question, ips []net.IP, ttl uint32) []byte {
	resp := make([]byte, 0, q.nameEnd+16*len(ips))

	// Header: same ID as the query, QR=1 (response), RA=1, RCODE=0,
	// QDCOUNT=1, ANCOUNT=len(ips), NSCOUNT=0, ARCOUNT=0.
	resp = append(resp, query[0], query[1]) // ID
	flags := uint16(flagQR | flagRA | rcodeOK)
	resp = append(resp, byte(flags>>8), byte(flags))
	resp = append(resp, 0, 1) // QDCOUNT
	resp = append(resp, byte(len(ips)>>8), byte(len(ips)))
	resp = append(resp, 0, 0) // NSCOUNT
	resp = append(resp, 0, 0) // ARCOUNT

	// Echo the original question section verbatim.
	resp = append(resp, query[12:q.nameEnd]...)

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue // skip anything that isn't a plain IPv4 address
		}
		// Answer: name (as a pointer back to the question's name at
		// offset 12), type A, class IN, TTL, RDLENGTH, RDATA.
		resp = append(resp, 0xC0, 0x0C)
		resp = append(resp, 0, qTypeA)
		resp = append(resp, 0, qClassIN)
		resp = append(resp, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
		resp = append(resp, 0, 4) // RDLENGTH
		resp = append(resp, ip4...)
	}

	return resp
}
