package dhcp

import (
	"net"
	"testing"
	"time"

	"cobweb/internal/config"
	"cobweb/internal/netstat"
)

type capture struct{ replies []*Packet }

func newCapturingServer(t *testing.T) (*Server, *capture, string, *config.Config) {
	t.Helper()
	cfg, segID := testConfigWithSegment(t)
	srv := New(cfg, segID)
	c := &capture{}
	srv.sendFn = func(b []byte) {
		p, err := ParsePacket(b)
		if err != nil {
			t.Fatalf("server sent an unparseable reply: %v", err)
		}
		c.replies = append(c.replies, p)
	}
	old := readARPTableFn
	readARPTableFn = func() ([]netstat.ARPEntry, error) { return nil, nil }
	t.Cleanup(func() { readARPTableFn = old })
	return srv, c, segID, cfg
}

func req(mt MessageType, mac string, requested, ciaddr, serverID string) *Packet {
	hw, _ := net.ParseMAC(mac)
	p := &Packet{Op: 1, HType: 1, HLen: 6, CHAddr: hw, MessageType: mt, CIAddr: net.IPv4zero.To4()}
	if requested != "" {
		p.RequestedIP = net.ParseIP(requested).To4()
	}
	if ciaddr != "" {
		p.CIAddr = net.ParseIP(ciaddr).To4()
	}
	if serverID != "" {
		p.ServerID = net.ParseIP(serverID).To4()
	}
	return p
}

func lastType(t *testing.T, c *capture) MessageType {
	t.Helper()
	if len(c.replies) == 0 {
		t.Fatal("expected a reply, got none")
	}
	return c.replies[len(c.replies)-1].MessageType
}

func TestRequestForWrongAddressIsNAKedNotSilentlyReassigned(t *testing.T) {
	srv, c, segID, cfg := newCapturingServer(t)
	_ = cfg.UpsertLease(config.Lease{MAC: "11:11:11:11:11:11", IP: "192.168.2.5", ExpiresAt: time.Now().Add(time.Hour).Unix(), SegmentID: segID})

	// INIT-REBOOT: a laptop that last lived on the house network asks for its old address.
	srv.handle(req(Request, "11:11:11:11:11:11", "192.168.1.77", "", ""))
	if got := lastType(t, c); got != NAK {
		t.Fatalf("stale-address REQUEST got %d, want NAK(%d) so the client restarts at once", got, NAK)
	}

	// The same device asking for what it actually holds is ACKed with that address.
	c.replies = nil
	srv.handle(req(Request, "11:11:11:11:11:11", "192.168.2.5", "", ""))
	if got := lastType(t, c); got != ACK {
		t.Fatalf("REQUEST for own lease got %d, want ACK", got)
	}
	if !c.replies[0].YIAddr.Equal(net.ParseIP("192.168.2.5")) {
		t.Fatalf("ACK yiaddr = %v, want 192.168.2.5", c.replies[0].YIAddr)
	}
}

func TestRenewalOfReservedAddressIsACKedAndOldDynamicAddressNAKed(t *testing.T) {
	srv, c, segID, cfg := newCapturingServer(t)
	if err := cfg.AddReservation(config.Reservation{MAC: "22:22:22:22:22:22", IP: "192.168.2.9", Hostname: "pc", SegmentID: segID}); err != nil {
		t.Fatal(err)
	}
	srv.handle(req(Request, "22:22:22:22:22:22", "", "192.168.2.9", ""))
	if lastType(t, c) != ACK {
		t.Fatal("renewal of the reserved address should be ACKed")
	}
	// It used to hold a pool address before the reservation was made.
	srv.handle(req(Request, "22:22:22:22:22:22", "192.168.2.44", "", ""))
	if lastType(t, c) != NAK {
		t.Fatal("request for a non-reserved address should be NAKed so the client re-DISCOVERs and picks up the reservation")
	}
}

func TestRequestForAnotherServerIsIgnored(t *testing.T) {
	srv, c, _, _ := newCapturingServer(t)
	srv.handle(req(Request, "33:33:33:33:33:33", "192.168.2.7", "", "192.168.2.99"))
	if len(c.replies) != 0 {
		t.Fatalf("answered a REQUEST addressed to a different DHCP server: %+v", c.replies)
	}
	// Addressed to us: answered.
	srv.handle(req(Request, "33:33:33:33:33:33", "192.168.2.2", "", "192.168.2.1"))
	if len(c.replies) != 1 {
		t.Fatal("REQUEST addressed to this server was not answered")
	}
}

func TestDeclineKeepsAddressOutOfPool(t *testing.T) {
	srv, c, _, _ := newCapturingServer(t)
	srv.handle(req(Discover, "44:44:44:44:44:44", "", "", ""))
	first := c.replies[0].YIAddr.String()

	// The client ARP-probed the offer, found it in use, and declines.
	srv.handle(req(Decline, "44:44:44:44:44:44", first, "", "192.168.2.1"))
	c.replies = nil
	srv.handle(req(Discover, "44:44:44:44:44:44", "", "", ""))
	if got := c.replies[0].YIAddr.String(); got == first {
		t.Fatalf("offered %s again right after the client declined it", got)
	}

	// Quarantine ends on its own.
	srv.mu.Lock()
	srv.declined[first] = time.Now().Add(-time.Second)
	srv.mu.Unlock()
	if srv.isDeclined(first) {
		t.Fatal("quarantine did not expire")
	}
}

func TestSlowHandlerStaysQuietForNormalTraffic(t *testing.T) {
	srv, c, _, _ := newCapturingServer(t)
	start := time.Now()
	srv.handle(req(Discover, "55:55:55:55:55:55", "", "", ""))
	if time.Since(start) > slowHandleWarn {
		t.Fatalf("a plain DISCOVER took %v", time.Since(start))
	}
	if lastType(t, c) != Offer {
		t.Fatal("DISCOVER should be answered with OFFER")
	}
}
