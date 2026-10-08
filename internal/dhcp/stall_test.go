package dhcp

import (
	"testing"
	"time"

	"cobweb/internal/config"
)

// A DHCP allocation must not wait on config.json being written. This used to
// fail: the dashboard's ARP poll (UpsertDiscoveredDevice) and every DHCP ACK
// (UpsertLease) rewrote the file while holding the lock that allocate()'s
// lookups need, so a slow or spun-down disk stalled DHCP for as long as the
// write took.
func TestAllocateDoesNotWaitForConfigWrites(t *testing.T) {
	cfg, segID := testConfigWithSegment(t)
	srv := New(cfg, segID)
	config.SetWriteDelayForTest(500 * time.Millisecond)
	defer config.SetWriteDelayForTest(0)

	now := time.Now().Unix()
	if err := cfg.UpsertDiscoveredDevice(config.DiscoveredDevice{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.2.50", SegmentID: segID, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.UpsertLease(config.Lease{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.2.2", Hostname: "pc", ExpiresAt: now + 3600, SegmentID: segID}); err != nil {
		t.Fatal(err)
	}
	// Let the background flusher start its (slow) write, then race it.
	time.Sleep(1200 * time.Millisecond)

	start := time.Now()
	if _, err := srv.allocate("33:33:33:33:33:33", "x", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.allocate("bb:bb:bb:bb:bb:bb", "pc", nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("allocate waited %v behind a config write; DHCP must not block on disk", d)
	}
}
