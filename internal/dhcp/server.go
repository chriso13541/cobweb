// Package dhcp implements a minimal DHCPv4 server sufficient to run a
// home/homelab network: DISCOVER -> OFFER -> REQUEST -> ACK, static
// reservations by MAC address, and a dynamic pool for everything else.
// It talks directly to the UDP socket rather than wrapping an external
// daemon, so all of its behavior is driven by cobweb's own config file.
//
// One Server instance serves exactly one LAN segment (one VLAN, one
// subnet, one pool) - a box with multiple segments runs multiple
// Server instances, each bound to its own interface via
// SO_BINDTODEVICE, same as the single-LAN case just replicated per
// segment. They all share the same underlying config/lease store.
package dhcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"cobweb/internal/config"
	"cobweb/internal/netstat"
	"cobweb/internal/status"
)

// Server is a running DHCP server bound to one LAN segment's broadcast
// domain.
type Server struct {
	cfg       *config.Config
	segmentID string
	conn      *net.UDPConn

	// Addresses a client DECLINEd (it found them already in use), mapped to
	// when the quarantine ends. Not persisted: a restart forgets them, and
	// the client will simply decline again if the conflict is still there.
	mu       sync.Mutex
	declined map[string]time.Time

	sendFn func([]byte) // test seam: capture replies instead of broadcasting them
}

// declineQuarantine is how long a declined address stays out of the pool.
const declineQuarantine = 10 * time.Minute

// slowHandleWarn is the handling time above which a packet is logged as slow.
const slowHandleWarn = 100 * time.Millisecond

// New creates a DHCP server for one specific LAN segment. It does not
// start listening until Run is called.
func New(cfg *config.Config, segmentID string) *Server {
	return &Server{cfg: cfg, segmentID: segmentID, declined: map[string]time.Time{}}
}

// segment looks up this server's current segment definition fresh from
// config every time it's needed, same "always read live" pattern used
// throughout cobweb - so changing a pool range or address in Settings
// takes effect without a restart. If the segment has been deleted
// since Run started, this returns an error; callers should treat that
// as "nothing to do right now" rather than crash.
func (s *Server) segment() (config.LANSegment, error) {
	seg, ok := s.cfg.SegmentByID(s.segmentID)
	if !ok {
		return config.LANSegment{}, fmt.Errorf("segment %s no longer exists", s.segmentID)
	}
	return seg, nil
}

// Run binds to UDP :67 on this segment's interface and serves requests
// until the process exits or an unrecoverable socket error occurs.
// Requires root (or CAP_NET_BIND_SERVICE) since port 67 is privileged.
func (s *Server) Run() error {
	seg, err := s.segment()
	if err != nil {
		status.SetDHCPSegment(s.segmentID, "", false, err)
		return fmt.Errorf("dhcp: %w", err)
	}

	// A box with multiple segments runs one of these Servers per
	// segment, all wanting port 67. net.ListenUDP alone would collide:
	// its bind() happens on the wildcard address before SO_BINDTODEVICE
	// gets a chance to scope anything, so a second segment's listener
	// would fail with "address already in use" even though it's meant
	// to end up on a completely different interface. SO_REUSEPORT has
	// to be set *before* bind to avoid that, which net.ListenUDP's
	// convenience wrapper doesn't allow - so this constructs the
	// socket by hand instead.
	conn, err := listenUDPReusePort(67)
	if err != nil {
		status.SetDHCPSegment(s.segmentID, seg.Name, false, err)
		return fmt.Errorf("dhcp[%s]: listen: %w", seg.Name, err)
	}
	s.conn = conn
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("dhcp[%s]: syscall conn: %w", seg.Name, err)
	}

	lanIf := seg.Interface
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		// Replies to clients that don't have an IP yet must go out as
		// broadcast. The kernel refuses broadcast sends on a UDP socket
		// unless SO_BROADCAST is explicitly set.
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		if sockErr != nil {
			return
		}
		// Scopes this specific socket to this segment's own interface,
		// so with SO_REUSEPORT already letting multiple segments share
		// port 67, each one still only ever sends/receives on its own
		// interface - no cross-segment traffic possible even though
		// they're all bound to the "same" address:port at the socket
		// level.
		sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, lanIf)
	}); err != nil {
		return fmt.Errorf("dhcp[%s]: control: %w", seg.Name, err)
	}
	if sockErr != nil {
		status.SetDHCPSegment(s.segmentID, seg.Name, false, sockErr)
		return fmt.Errorf("dhcp[%s]: socket setup (SO_BROADCAST/SO_BINDTODEVICE on %s): %w", seg.Name, lanIf, sockErr)
	}

	status.SetDHCPSegment(s.segmentID, seg.Name, true, nil)
	log.Printf("dhcp[%s]: listening on :67 (bound to %s)", seg.Name, lanIf)

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("dhcp[%s]: read error: %v", seg.Name, err)
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

// SO_REUSEPORT isn't exposed by Go's standard syscall package on this
// platform, so it's defined here directly - this is the stable Linux
// kernel ABI value (asm-generic/socket.h), not something that varies
// or changes between kernel versions.
const soReusePort = 0xf

// listenUDPReusePort creates a UDP socket bound to 0.0.0.0:port with
// SO_REUSEPORT set before bind - net.ListenUDP can't do this itself,
// since by the time it hands back a *net.UDPConn, bind() has already
// happened with no chance to set that option first. This is what lets
// multiple LAN segments' DHCP servers all claim port 67 without
// colliding, each later scoped to its own interface via
// SO_BINDTODEVICE (set separately, after this returns).
func listenUDPReusePort(port int) (*net.UDPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_REUSEPORT: %w", err)
	}

	sa := &syscall.SockaddrInet4{Port: port} // Addr left zero: 0.0.0.0
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind :%d: %w", port, err)
	}

	// Hand the raw fd to the standard library as a *os.File, then let
	// net wrap it as a proper *net.UDPConn - this gives back the same
	// type Run() already knows how to use (ReadFromUDP, WriteToUDP,
	// SyscallConn for the SO_BROADCAST/SO_BINDTODEVICE calls that
	// follow), it's just constructed differently underneath.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("dhcp-udp-%d", port))
	defer file.Close() // FilePacketConn dup()s the fd, so closing our copy here is correct and expected

	pc, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("FilePacketConn: %w", err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T", pc)
	}
	return conn, nil
}

func (s *Server) handle(pkt *Packet) {
	start := time.Now()
	switch pkt.MessageType {
	case Discover:
		s.handleDiscover(pkt)
	case Request:
		s.handleRequest(pkt)
	case Decline:
		s.handleDecline(pkt)
	case Release:
		// Leases naturally expire; keeping the record also means the
		// device gets the same address back when it returns.
		log.Printf("dhcp: RELEASE from %s (%s)", pkt.CHAddr, pkt.CIAddr)
	}
	if d := time.Since(start); d > slowHandleWarn {
		log.Printf("dhcp: SLOW: handling %d from %s took %v", pkt.MessageType, pkt.CHAddr, d.Round(time.Millisecond))
	}
}

// handleDecline processes a client reporting that the address it was given
// is already in use on the wire (it ARP-probed it and got an answer). Without
// this, the pool scan would offer the very same address again, the client
// would decline again, and each round trip costs it a multi-second back-off.
func (s *Server) handleDecline(pkt *Packet) {
	mac := pkt.CHAddr.String()
	if pkt.ServerID != nil {
		if sid, err := s.serverIP(); err == nil && !pkt.ServerID.Equal(sid) {
			return // declining another server's offer
		}
	}
	if pkt.RequestedIP == nil {
		return
	}
	ip := pkt.RequestedIP.String()
	log.Printf("dhcp: DECLINE from %s for %s - address is in use by another device; keeping it out of the pool for %s", mac, ip, declineQuarantine)
	if r, ok := s.cfg.ReservationForMAC(mac); ok && r.IP == ip {
		log.Printf("dhcp: WARNING: %s declined its RESERVED address %s; another device is using it, so this client cannot get its reservation until that is fixed", mac, ip)
	}
	s.mu.Lock()
	s.declined[ip] = time.Now().Add(declineQuarantine)
	s.mu.Unlock()
}

// isDeclined reports whether ip is in the post-DECLINE quarantine.
func (s *Server) isDeclined(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.declined[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(s.declined, ip)
		return false
	}
	return true
}

func (s *Server) handleDiscover(pkt *Packet) {
	mac := pkt.CHAddr.String()
	log.Printf("dhcp: DISCOVER from %s xid=%x (%s)", mac, pkt.XID, pkt.Hostname)
	ip, err := s.allocate(mac, pkt.Hostname, pkt.RequestedIP)
	if err != nil {
		log.Printf("dhcp: no address available for %s: %v", mac, err)
		return
	}

	reply, err := s.buildOfferOrACK(pkt, ip, Offer)
	if err != nil {
		log.Printf("dhcp: %v", err)
		return
	}
	s.send(reply)
	log.Printf("dhcp: OFFER %s -> %s", mac, ip)
}

func (s *Server) handleRequest(pkt *Packet) {
	mac := pkt.CHAddr.String()

	// A REQUEST carrying a server identifier is the client's answer to
	// someone's OFFER (RFC 2131 4.3.2). If it chose a different server, this
	// one must stay silent - replying anyway would hand the client a second,
	// conflicting answer.
	if pkt.ServerID != nil {
		if sid, err := s.serverIP(); err == nil && !pkt.ServerID.Equal(sid) {
			return
		}
	}

	// Determine what IP we're confirming: either the client's requested
	// IP (initial REQUEST after an OFFER), or its current CIAddr (a
	// renewal from a client that already has a lease).
	var wantIP net.IP
	if pkt.RequestedIP != nil {
		wantIP = pkt.RequestedIP
	} else if !pkt.CIAddr.Equal(net.IPv4zero) {
		wantIP = pkt.CIAddr
	}

	state := "selecting"
	switch {
	case pkt.ServerID == nil && pkt.CIAddr.Equal(net.IPv4zero):
		state = "init-reboot"
	case pkt.ServerID == nil:
		state = "renewing"
	}
	log.Printf("dhcp: REQUEST from %s xid=%x for %v (%s, %s)", mac, pkt.XID, wantIP, state, pkt.Hostname)

	ip, err := s.allocate(mac, pkt.Hostname, wantIP)
	if err == nil && wantIP != nil && !ip.Equal(wantIP) {
		// The client wants an address we are not going to give it (its old
		// lease from another network, a changed reservation, an address that
		// is now taken). The protocol answer is a NAK, which makes the client
		// drop it and start over at once. Quietly ACKing a different address
		// instead leaves many clients waiting out their own retry timers.
		err = fmt.Errorf("%s is not available to this client (it would get %s)", wantIP, ip)
	}
	if err != nil {
		log.Printf("dhcp: NAK for %s: %v", mac, err)
		serverID, sErr := s.serverIP()
		if sErr != nil {
			return
		}
		nak := BuildReply(pkt, ReplyOpts{
			MessageType: NAK,
			ServerID:    serverID,
		})
		s.send(nak)
		return
	}

	reply, err := s.buildOfferOrACK(pkt, ip, ACK)
	if err != nil {
		log.Printf("dhcp: %v", err)
		return
	}
	s.send(reply)

	hostname := pkt.Hostname
	if hostname == "" {
		hostname = "(unknown)"
	}
	expires := time.Now().Add(time.Duration(s.cfg.Snapshot().LeaseSeconds) * time.Second).Unix()
	if err := s.cfg.UpsertLease(config.Lease{
		MAC:       mac,
		IP:        ip.String(),
		Hostname:  hostname,
		ExpiresAt: expires,
		SegmentID: s.segmentID,
	}); err != nil {
		log.Printf("dhcp: failed to persist lease for %s: %v", mac, err)
	}
	log.Printf("dhcp: ACK %s -> %s (%s)", mac, ip, hostname)
}

// allocate returns the IP that should be assigned to mac, on this
// server's own segment: a static reservation if one exists *for this
// segment* (a reservation tagged for a different segment is ignored
// here - a device showing up on the wrong VLAN port shouldn't get
// handed an IP that belongs to a different subnet), its existing
// active lease on this segment if it still has one, the specifically
// requested IP if that's free and in this segment's pool, or the next
// free address in this segment's pool.
// readARPTableFn is a seam for tests: production code always calls
// the real netstat.ReadARPTable, but tests can substitute synthetic
// ARP data without needing an actual kernel ARP table to exist.
var readARPTableFn = netstat.ReadARPTable

// arpTakenIPs returns the set of IPs on the given interface that
// currently have a live ARP entry belonging to some MAC other than
// excludeMAC - addresses claimed by a device outside cobweb's own
// DHCP records entirely, most commonly something set by hand (like a
// manually-assigned static IP in a device's own network settings).
//
// This exists to close a real failure mode: without it, the pool
// allocator only ever checks its own Leases/Reservations, so it can
// happily offer an address a static device is already sitting on.
// The new client ARP-probes the offered address, finds it taken,
// declines, and retries - landing right back on the same bad offer
// forever, since cobweb's own records never change. Checking the
// live ARP table before offering closes that loop.
func arpTakenIPs(iface, excludeMAC string) map[string]bool {
	entries, err := readARPTableFn()
	if err != nil {
		return map[string]bool{} // fail open - don't block allocation entirely just because this read failed
	}
	return arpTakenIPsFromEntries(entries, iface, excludeMAC)
}

func arpTakenIPsFromEntries(entries []netstat.ARPEntry, iface, excludeMAC string) map[string]bool {
	taken := map[string]bool{}
	for _, e := range entries {
		if e.Interface == iface && e.MAC != excludeMAC {
			taken[e.IP] = true
		}
	}
	return taken
}

func (s *Server) allocate(mac, hostname string, requested net.IP) (net.IP, error) {
	if r, ok := s.cfg.ReservationForMAC(mac); ok && r.SegmentID == s.segmentID {
		return net.ParseIP(r.IP), nil
	}

	if l, ok := s.cfg.LeaseForMAC(mac); ok && l.SegmentID == s.segmentID {
		if time.Now().Unix() < l.ExpiresAt || requested == nil || requested.String() == l.IP {
			return net.ParseIP(l.IP), nil
		}
	}

	seg, err := s.segment()
	if err != nil {
		return nil, err
	}
	arpTaken := arpTakenIPs(seg.Interface, mac)

	if requested != nil && s.inPool(requested) && !s.cfg.IPInUse(requested.String(), mac) && !arpTaken[requested.String()] && !s.isDeclined(requested.String()) {
		return requested, nil
	}

	start, end, err := s.cfg.ParsePoolRangeForSegment(s.segmentID)
	if err != nil {
		return nil, err
	}
	for ip := cloneIP(start); ipLTE(ip, end); ip = nextIP(ip) {
		candidate := ip.String()
		if candidate == seg.Address {
			continue // never hand out the gateway's own address
		}
		if s.cfg.IPInUse(candidate, mac) {
			continue
		}
		if arpTaken[candidate] {
			continue // claimed by a device outside cobweb's own DHCP records - e.g. a manually assigned static IP
		}
		if s.isDeclined(candidate) {
			continue // a client found it in use on the wire (DECLINE)
		}
		return ip, nil
	}
	return nil, fmt.Errorf("pool exhausted")
}

func (s *Server) inPool(ip net.IP) bool {
	start, end, err := s.cfg.ParsePoolRangeForSegment(s.segmentID)
	if err != nil {
		return false
	}
	return ipLTE(start, ip) && ipLTE(ip, end)
}

func (s *Server) buildOfferOrACK(req *Packet, ip net.IP, mt MessageType) ([]byte, error) {
	seg, err := s.segment()
	if err != nil {
		return nil, err
	}
	serverID, err := s.serverIP()
	if err != nil {
		return nil, err
	}
	return BuildReply(req, ReplyOpts{
		MessageType: mt,
		YourIP:      ip,
		ServerID:    serverID,
		SubnetMask:  net.ParseIP(seg.SubnetMask),
		Router:      net.ParseIP(seg.Address),
		DNSServer:   net.ParseIP(seg.Address), // cobweb runs one shared resolver, reachable via every segment's own gateway
		LeaseTime:   uint32(s.cfg.Snapshot().LeaseSeconds),
	}), nil
}

func (s *Server) serverIP() (net.IP, error) {
	seg, err := s.segment()
	if err != nil {
		return nil, err
	}
	return net.ParseIP(seg.Address), nil
}

// send broadcasts the reply. Home-network DHCP clients before they have
// an address can only be reached via broadcast. It targets this
// segment's own directed broadcast address (e.g. 192.168.20.255)
// rather than the global 255.255.255.255 - combined with
// SO_BINDTODEVICE in Run, this guarantees the reply goes out this
// segment's interface only.
func (s *Server) send(b []byte) {
	if s.sendFn != nil {
		s.sendFn(b)
		return
	}
	seg, err := s.segment()
	if err != nil {
		log.Printf("dhcp: send: %v", err)
		return
	}
	bcast := directedBroadcast(net.ParseIP(seg.Address), net.ParseIP(seg.SubnetMask))
	dst := &net.UDPAddr{IP: bcast, Port: 68}
	if _, err := s.conn.WriteToUDP(b, dst); err != nil {
		log.Printf("dhcp: send error: %v", err)
	}
}

// directedBroadcast computes the broadcast address for a given IP and
// subnet mask, e.g. 192.168.2.1 + 255.255.255.0 -> 192.168.2.255.
func directedBroadcast(ip, mask net.IP) net.IP {
	ip4 := ip.To4()
	mask4 := mask.To4()
	if ip4 == nil || mask4 == nil {
		return net.IPv4bcast // fall back to global broadcast if config is malformed
	}
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip4[i] | ^mask4[i]
	}
	return out
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
