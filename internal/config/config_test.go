package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func tempConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "config.json")
}

func TestDefaultHasOneSegment(t *testing.T) {
	c := Default(tempConfigPath(t))
	if len(c.LANSegments) != 1 {
		t.Fatalf("got %d segments, want 1", len(c.LANSegments))
	}
	seg := c.LANSegments[0]
	if seg.ID == "" {
		t.Fatal("segment ID should be generated, got empty string")
	}
	if seg.Interface != "enp1s0" || seg.Address != "192.168.2.1" {
		t.Fatalf("unexpected default segment: %+v", seg)
	}
}

func TestMigratesOldSingleLANConfig(t *testing.T) {
	path := tempConfigPath(t)
	// Simulates a config.json written by a pre-VLAN version of cobweb -
	// old top-level keys, no lan_segments at all.
	old := map[string]any{
		"wan_interface": "wlp2s0",
		"lan_interface": "enp1s0",
		"lan_address":   "192.168.2.1",
		"subnet_mask":   "255.255.255.0",
		"pool_start":    "192.168.2.10",
		"pool_end":      "192.168.2.254",
		"domain":        "lan",
		"lease_seconds": 86400,
		"dns_mode":      "forward",
		"listen_addr":   "0.0.0.0:8070",
		"reservations": []map[string]any{
			{"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.2.50", "hostname": "nas"},
		},
		"leases": []map[string]any{
			{"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.2.60", "hostname": "laptop", "expires_at": 9999999999},
		},
	}
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, b, 0640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed on legacy config: %v", err)
	}

	if len(c.LANSegments) != 1 {
		t.Fatalf("got %d segments after migration, want 1", len(c.LANSegments))
	}
	seg := c.LANSegments[0]
	if seg.Interface != "enp1s0" || seg.Address != "192.168.2.1" || seg.PoolStart != "192.168.2.10" {
		t.Fatalf("migrated segment doesn't match old fields: %+v", seg)
	}

	// Pre-existing reservations/leases should be tagged with the
	// migrated segment's ID, not left blank.
	if len(c.Reservations) != 1 || c.Reservations[0].SegmentID != seg.ID {
		t.Fatalf("reservation wasn't tagged with migrated segment ID: %+v", c.Reservations)
	}
	if len(c.Leases) != 1 || c.Leases[0].SegmentID != seg.ID {
		t.Fatalf("lease wasn't tagged with migrated segment ID: %+v", c.Leases)
	}

	// The migration should have persisted to disk, so re-loading
	// doesn't need to migrate again.
	c2, err := Load(path)
	if err != nil {
		t.Fatalf("re-load after migration failed: %v", err)
	}
	if len(c2.LANSegments) != 1 || c2.LANSegments[0].ID != seg.ID {
		t.Fatalf("migration didn't persist correctly: %+v", c2.LANSegments)
	}
}

func TestAddAndRemoveLANSegment(t *testing.T) {
	c := Default(tempConfigPath(t))
	before := len(c.LANSegments)

	added, err := c.AddLANSegment(LANSegment{
		Name:       "IoT",
		Interface:  "enp1s0.20",
		Address:    "192.168.20.1",
		SubnetMask: "255.255.255.0",
		PoolStart:  "192.168.20.10",
		PoolEnd:    "192.168.20.254",
		Domain:     "iot.lan",
	})
	if err != nil {
		t.Fatalf("AddLANSegment failed: %v", err)
	}
	if added.ID == "" {
		t.Fatal("AddLANSegment should generate an ID")
	}
	if len(c.LANSegments) != before+1 {
		t.Fatalf("got %d segments, want %d", len(c.LANSegments), before+1)
	}

	found, ok := c.SegmentByID(added.ID)
	if !ok || found.Name != "IoT" {
		t.Fatalf("SegmentByID didn't find the newly added segment: %+v ok=%v", found, ok)
	}

	if err := c.RemoveLANSegment(added.ID); err != nil {
		t.Fatalf("RemoveLANSegment failed: %v", err)
	}
	if len(c.LANSegments) != before {
		t.Fatalf("got %d segments after removal, want %d", len(c.LANSegments), before)
	}
	if _, ok := c.SegmentByID(added.ID); ok {
		t.Fatal("removed segment should no longer be found by ID")
	}
}

func TestSegmentIDsAreUniqueAndStableAcrossRename(t *testing.T) {
	c := Default(tempConfigPath(t))
	seg, err := c.AddLANSegment(LANSegment{
		Name: "Trusted", Interface: "enp1s0.10", Address: "192.168.10.1",
		SubnetMask: "255.255.255.0", PoolStart: "192.168.10.10", PoolEnd: "192.168.10.254", Domain: "lan",
	})
	if err != nil {
		t.Fatalf("AddLANSegment: %v", err)
	}
	originalID := seg.ID

	// Renaming (and changing other editable fields) shouldn't touch ID.
	updated := seg
	updated.Name = "Trusted-Renamed"
	updated.PoolEnd = "192.168.10.200"
	if err := c.UpdateLANSegment(originalID, updated); err != nil {
		t.Fatalf("UpdateLANSegment: %v", err)
	}

	got, ok := c.SegmentByID(originalID)
	if !ok {
		t.Fatal("segment should still be findable by its original ID after rename")
	}
	if got.Name != "Trusted-Renamed" || got.PoolEnd != "192.168.10.200" {
		t.Fatalf("update didn't apply: %+v", got)
	}
	if got.ID != originalID {
		t.Fatalf("ID changed on update: got %s, want %s", got.ID, originalID)
	}
}

func TestParsePoolRangeForSegment(t *testing.T) {
	c := Default(tempConfigPath(t))
	segID := c.LANSegments[0].ID

	start, end, err := c.ParsePoolRangeForSegment(segID)
	if err != nil {
		t.Fatalf("ParsePoolRangeForSegment: %v", err)
	}
	if start.String() != "192.168.2.10" || end.String() != "192.168.2.254" {
		t.Fatalf("got range %s-%s, want 192.168.2.10-192.168.2.254", start, end)
	}

	if _, _, err := c.ParsePoolRangeForSegment("nonexistent-segment-id"); err == nil {
		t.Fatal("expected an error for a nonexistent segment ID, got nil")
	}
}

func TestIPInUseChecksAcrossAllSegments(t *testing.T) {
	c := Default(tempConfigPath(t))
	seg2, err := c.AddLANSegment(LANSegment{
		Name: "IoT", Interface: "enp1s0.20", Address: "192.168.20.1",
		SubnetMask: "255.255.255.0", PoolStart: "192.168.20.10", PoolEnd: "192.168.20.254", Domain: "lan",
	})
	if err != nil {
		t.Fatalf("AddLANSegment: %v", err)
	}

	if err := c.AddReservation(Reservation{MAC: "aa:bb:cc:dd:ee:99", IP: "192.168.20.50", SegmentID: seg2.ID}); err != nil {
		t.Fatalf("AddReservation: %v", err)
	}

	if !c.IPInUse("192.168.20.50", "some-other-mac") {
		t.Fatal("expected 192.168.20.50 to be reported in use")
	}
	if c.IPInUse("192.168.20.50", "aa:bb:cc:dd:ee:99") {
		t.Fatal("IP shouldn't be reported in use when excluding its own owner's MAC")
	}
}
