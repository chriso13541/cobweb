package dhcp

import (
	"net"
	"testing"
	"time"

	"cobweb/internal/config"
	"cobweb/internal/netstat"
)

func testConfigWithSegment(t *testing.T) (*config.Config, string) {
	t.Helper()
	path := t.TempDir() + "/config.json"
	cfg := config.Default(path)
	seg, err := cfg.AddLANSegment(config.LANSegment{
		Name: "Test", Interface: "eth-test", Address: "192.168.2.1",
		SubnetMask: "255.255.255.0", PoolStart: "192.168.2.2", PoolEnd: "192.168.2.10", Domain: "lan",
	})
	if err != nil {
		t.Fatalf("AddLANSegment: %v", err)
	}
	return cfg, seg.ID
}

func TestArpTakenIPsFromEntries(t *testing.T) {
	entries := []netstat.ARPEntry{
		{IP: "192.168.2.3", MAC: "aa:aa:aa:aa:aa:aa", Interface: "eth-test"},
		{IP: "192.168.2.4", MAC: "bb:bb:bb:bb:bb:bb", Interface: "eth-other"}, // different interface - shouldn't count
		{IP: "192.168.2.5", MAC: "cc:cc:cc:cc:cc:cc", Interface: "eth-test"},
	}

	taken := arpTakenIPsFromEntries(entries, "eth-test", "zz:zz:zz:zz:zz:zz")
	if !taken["192.168.2.3"] {
		t.Error("192.168.2.3 should be taken (different MAC, matching interface)")
	}
	if taken["192.168.2.4"] {
		t.Error("192.168.2.4 should NOT be taken (different interface)")
	}
	if !taken["192.168.2.5"] {
		t.Error("192.168.2.5 should be taken (different MAC, matching interface)")
	}
}

func TestArpTakenIPsExcludesOwnMAC(t *testing.T) {
	// A device renewing its own existing address would show up in its
	// own ARP entry - that should never count as "taken" against
	// itself.
	entries := []netstat.ARPEntry{
		{IP: "192.168.2.3", MAC: "aa:aa:aa:aa:aa:aa", Interface: "eth-test"},
	}
	taken := arpTakenIPsFromEntries(entries, "eth-test", "aa:aa:aa:aa:aa:aa")
	if taken["192.168.2.3"] {
		t.Error("shouldn't exclude an IP based on the requesting device's own ARP entry")
	}
}

// TestAllocateSkipsStaticallyConfiguredIP reproduces the exact bug
// report: a device manually/statically assigned an IP outside of
// DHCP entirely (so cobweb has no Lease or Reservation for it) still
// needs to be avoided by the pool allocator, using the live ARP
// table as the source of truth cobweb's own records don't have.
func TestAllocateSkipsStaticallyConfiguredIP(t *testing.T) {
	cfg, segID := testConfigWithSegment(t)
	srv := New(cfg, segID)

	// Simulate: 192.168.2.2 already has a real DHCP lease (from
	// cobweb's own records), and 192.168.2.3 is claimed by a
	// manually-configured static device that cobweb has never issued
	// a lease for - only visible via ARP, exactly like the report.
	if err := cfg.UpsertLease(config.Lease{
		MAC: "11:11:11:11:11:11", IP: "192.168.2.2", Hostname: "stronghold",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), SegmentID: segID,
	}); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}

	oldReadARP := readARPTableFn
	defer func() { readARPTableFn = oldReadARP }()
	readARPTableFn = func() ([]netstat.ARPEntry, error) {
		return []netstat.ARPEntry{
			{IP: "192.168.2.3", MAC: "22:22:22:22:22:22", Interface: "eth-test"}, // the manually-configured Windows PC
		}, nil
	}

	// A brand new device (iron-golem) requests an address - should
	// skip .2 (taken by lease) AND .3 (taken by static/ARP-only
	// device), landing on .4.
	ip, err := srv.allocate("33:33:33:33:33:33", "iron-golem", nil)
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}
	if got := ip.String(); got != "192.168.2.4" {
		t.Fatalf("got %s, want 192.168.2.4 (should skip both the leased .2 and the ARP-only-claimed .3)", got)
	}
}

// TestAllocateHonorsExplicitRequestUnlessARPConflict checks the other
// code path: a client explicitly requesting a specific address (the
// DHCPREQUEST path, not just a fresh pool scan) should also be
// rejected if that address conflicts on ARP.
func TestAllocateHonorsExplicitRequestUnlessARPConflict(t *testing.T) {
	cfg, segID := testConfigWithSegment(t)
	srv := New(cfg, segID)

	oldReadARP := readARPTableFn
	defer func() { readARPTableFn = oldReadARP }()
	readARPTableFn = func() ([]netstat.ARPEntry, error) {
		return []netstat.ARPEntry{
			{IP: "192.168.2.5", MAC: "aa:aa:aa:aa:aa:aa", Interface: "eth-test"},
		}, nil
	}

	// Requesting an address that's fine should be honored as-is.
	ip, err := srv.allocate("bb:bb:bb:bb:bb:bb", "test", net.ParseIP("192.168.2.6"))
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}
	if got := ip.String(); got != "192.168.2.6" {
		t.Fatalf("got %s, want 192.168.2.6 (explicit request with no conflict should be honored)", got)
	}

	// Requesting an address with a genuine ARP conflict should NOT be
	// honored - falls through to the pool scan instead.
	ip, err = srv.allocate("cc:cc:cc:cc:cc:cc", "test", net.ParseIP("192.168.2.5"))
	if err != nil {
		t.Fatalf("allocate failed: %v", err)
	}
	if got := ip.String(); got == "192.168.2.5" {
		t.Fatal("should NOT have honored a requested address that conflicts on ARP")
	}
}
