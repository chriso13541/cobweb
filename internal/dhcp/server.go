// Package dhcp implements a minimal DHCPv4 server sufficient to run a
// home/homelab network: DISCOVER -> OFFER -> REQUEST -> ACK, static
// reservations by MAC address, and a dynamic pool for everything else.
// It talks directly to the UDP socket rather than wrapping an external
// daemon, so all of its behavior is driven by cobweb's own config file.
package dhcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"cobweb/internal/config"
)

// Server is a running DHCP server bound to one interface's broadcast
// domain.
type Server struct {
	cfg  *config.Config
	conn *net.UDPConn
}

// New creates a DHCP server. It does not start listening until Run is
// called.
func New(cfg *config.Config) *Server {
	return &Server{cfg: cfg}
}

// Run binds to UDP :67 and serves requests until the process exits or
// an unrecoverable socket error occurs. Requires root (or
// CAP_NET_BIND_SERVICE) since port 67 is a privileged port.
func (s *Server) Run() error {
	addr := &net.UDPAddr{Port: 67, IP: net.IPv4zero}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("dhcp: listen: %w", err)
	}
	s.conn = conn
	defer conn.Close()

	// Replies to clients that don't have an IP yet must go out as
	// broadcast (255.255.255.255:68). The kernel refuses broadcast
	// sends on a UDP socket unless SO_BROADCAST is explicitly set.
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("dhcp: syscall conn: %w", err)
	}
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	}); err != nil {
		return fmt.Errorf("dhcp: control: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("dhcp: set SO_BROADCAST: %w", sockErr)
	}

	log.Printf("dhcp: listening on :67")

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("dhcp: read error: %v", err)
			continue
		}
		pkt, err := ParsePacket(buf[:n])
		if err != nil {
			// Malformed or non-DHCP traffic on the port; ignore rather
			// than crash the server.
			continue
		}
		s.handle(pkt)
	}
}

func (s *Server) handle(pkt *Packet) {
	switch pkt.MessageType {
	case Discover:
		s.handleDiscover(pkt)
	case Request:
		s.handleRequest(pkt)
	case Release:
		// Leases naturally expire; explicit RELEASE handling can be
		// added later if a client's early-release behavior matters.
	}
}

func (s *Server) handleDiscover(pkt *Packet) {
	mac := pkt.CHAddr.String()
	ip, err := s.allocate(mac, pkt.Hostname, pkt.RequestedIP)
	if err != nil {
		log.Printf("dhcp: no address available for %s: %v", mac, err)
		return
	}

	reply := s.buildOfferOrACK(pkt, ip, Offer)
	s.send(reply)
	log.Printf("dhcp: OFFER %s -> %s", mac, ip)
}

func (s *Server) handleRequest(pkt *Packet) {
	mac := pkt.CHAddr.String()

	// Determine what IP we're confirming: either the client's requested
	// IP (initial REQUEST after an OFFER), or its current CIAddr (a
	// renewal from a client that already has a lease).
	var wantIP net.IP
	if pkt.RequestedIP != nil {
		wantIP = pkt.RequestedIP
	} else if !pkt.CIAddr.Equal(net.IPv4zero) {
		wantIP = pkt.CIAddr
	}

	ip, err := s.allocate(mac, pkt.Hostname, wantIP)
	if err != nil {
		log.Printf("dhcp: NAK for %s: %v", mac, err)
		nak := BuildReply(pkt, ReplyOpts{
			MessageType: NAK,
			ServerID:    s.serverIP(),
		})
		s.send(nak)
		return
	}

	reply := s.buildOfferOrACK(pkt, ip, ACK)
	s.send(reply)

	hostname := pkt.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	expires := time.Now().Add(time.Duration(s.cfg.LeaseSeconds) * time.Second).Unix()
	if err := s.cfg.UpsertLease(config.Lease{
		MAC:       mac,
		IP:        ip.String(),
		Hostname:  hostname,
		ExpiresAt: expires,
	}); err != nil {
		log.Printf("dhcp: failed to persist lease for %s: %v", mac, err)
	}
	log.Printf("dhcp: ACK %s -> %s (%s)", mac, ip, hostname)
}

// allocate returns the IP that should be assigned to mac: a static
// reservation if one exists, its existing active lease if it still has
// one, the specifically requested IP if that's free, or the next free
// address in the pool.
func (s *Server) allocate(mac, hostname string, requested net.IP) (net.IP, error) {
	if r, ok := s.cfg.ReservationForMAC(mac); ok {
		return net.ParseIP(r.IP), nil
	}

	if l, ok := s.cfg.LeaseForMAC(mac); ok {
		if time.Now().Unix() < l.ExpiresAt || requested == nil || requested.String() == l.IP {
			return net.ParseIP(l.IP), nil
		}
	}

	if requested != nil && s.inPool(requested) && !s.cfg.IPInUse(requested.String(), mac) {
		return requested, nil
	}

	start, end, err := s.cfg.ParsePoolRange()
	if err != nil {
		return nil, err
	}
	for ip := cloneIP(start); ipLTE(ip, end); ip = nextIP(ip) {
		candidate := ip.String()
		if candidate == s.cfg.LANAddress {
			continue // never hand out the gateway's own address
		}
		if !s.cfg.IPInUse(candidate, mac) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("pool exhausted")
}

func (s *Server) inPool(ip net.IP) bool {
	start, end, err := s.cfg.ParsePoolRange()
	if err != nil {
		return false
	}
	return ipLTE(start, ip) && ipLTE(ip, end)
}

func (s *Server) buildOfferOrACK(req *Packet, ip net.IP, mt MessageType) []byte {
	snap := s.cfg.Snapshot()
	return BuildReply(req, ReplyOpts{
		MessageType: mt,
		YourIP:      ip,
		ServerID:    s.serverIP(),
		SubnetMask:  net.ParseIP(snap.SubnetMask),
		Router:      net.ParseIP(snap.LANAddress),
		DNSServer:   net.ParseIP(snap.LANAddress), // cobweb runs its own resolver
		LeaseTime:   uint32(snap.LeaseSeconds),
	})
}

func (s *Server) serverIP() net.IP {
	return net.ParseIP(s.cfg.Snapshot().LANAddress)
}

// send broadcasts the reply. Home-network DHCP clients before they have
// an address can only be reached via broadcast, so this always targets
// 255.255.255.255:68 rather than trying to unicast to an address the
// client doesn't have yet.
func (s *Server) send(b []byte) {
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	if _, err := s.conn.WriteToUDP(b, dst); err != nil {
		log.Printf("dhcp: send error: %v", err)
	}
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func nextIP(ip net.IP) net.IP {
	out := cloneIP(ip)
	v := binary.BigEndian.Uint32(out)
	v++
	binary.BigEndian.PutUint32(out, v)
	return out
}

func ipLTE(a, b net.IP) bool {
	av := binary.BigEndian.Uint32(a.To4())
	bv := binary.BigEndian.Uint32(b.To4())
	return av <= bv
}
