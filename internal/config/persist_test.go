package config

import (
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func readLeases(t *testing.T, path string) []Lease {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c struct{ Leases []Lease }
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("config on disk is not valid JSON: %v", err)
	}
	return c.Leases
}

func TestUpsertLeaseIsDeferredThenFlushed(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := Default(path)
	if err := c.UpsertLease(Lease{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.2.20", ExpiresAt: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if l, ok := reloaded.LeaseForMAC("aa:aa:aa:aa:aa:aa"); !ok || l.IP != "192.168.2.20" {
		t.Fatalf("lease not persisted by Flush: %+v ok=%v", l, ok)
	}
}

func TestBackgroundFlushWritesWithoutExplicitFlush(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := Default(path)
	_ = c.UpsertLease(Lease{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.2.20"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(readLeases(t, path)) == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("background flusher never wrote the lease")
}

func TestBurstOfLeasesIsOneWrite(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := Default(path)
	var writes atomic.Int32
	hook := func(n string, b []byte, p os.FileMode) error { writes.Add(1); return os.WriteFile(n, b, p) }
	writeFileHook.Store(&hook)
	defer writeFileHook.Store(nil)
	for i := 0; i < 50; i++ {
		_ = c.UpsertLease(Lease{MAC: "aa:aa:aa:aa:aa:" + string(rune('a'+i%26)) + "0", IP: "192.168.2.20"})
	}
	time.Sleep(2500 * time.Millisecond)
	if n := writes.Load(); n != 1 {
		t.Fatalf("50 lease updates produced %d writes, want 1", n)
	}
}

func TestUnchangedDiscoveredDeviceDoesNotRewrite(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := Default(path)
	d := DiscoveredDevice{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.2.50", SegmentID: "s", LastSeen: 1000}
	_ = c.UpsertDiscoveredDevice(d)
	gen := c.mutGen.Load()
	d.LastSeen = 1010 // a poll a few seconds later
	_ = c.UpsertDiscoveredDevice(d)
	if c.mutGen.Load() != gen {
		t.Fatal("a poll with nothing new marked the config dirty")
	}
	d.IP = "192.168.2.51" // it moved
	_ = c.UpsertDiscoveredDevice(d)
	if c.mutGen.Load() == gen {
		t.Fatal("a changed IP was not recorded")
	}
	d.LastSeen = 1010 + discoveredRefreshSecs
	gen = c.mutGen.Load()
	_ = c.UpsertDiscoveredDevice(d)
	if c.mutGen.Load() == gen {
		t.Fatal("stale LastSeen was never refreshed")
	}
}

func TestStaleSnapshotNeverOverwritesNewer(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := Default(path)
	if err := c.writeSnapshot([]byte(`{"leases":[{"mac":"new"}]}`), 5); err != nil {
		t.Fatal(err)
	}
	if err := c.writeSnapshot([]byte(`{"leases":[{"mac":"old"}]}`), 3); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != `{"leases":[{"mac":"new"}]}` {
		t.Fatalf("older snapshot overwrote newer one: %s", b)
	}
}

func TestSettingsSaveStillSynchronousAndIncludesPendingLeases(t *testing.T) {
	path := t.TempDir() + "/config.json"
	c := Default(path)
	_ = c.UpsertLease(Lease{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.2.20"})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if len(readLeases(t, path)) != 1 {
		t.Fatal("a synchronous save did not include the pending lease")
	}
	gen := c.mutGen.Load()
	if c.flushedGen.Load() != gen {
		t.Fatal("synchronous save left the config marked dirty")
	}
}
