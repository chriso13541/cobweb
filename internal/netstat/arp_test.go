package netstat

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestReadARPTableParsesCompleteEntries(t *testing.T) {
	fixture := `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         AA:BB:CC:DD:EE:01     *        enp1s0.99
192.168.2.50     0x1         0x2         aa:bb:cc:dd:ee:02     *        enp1s0.10
`
	entries, err := readARPTableFrom(writeFixture(t, fixture))
	if err != nil {
		t.Fatalf("readARPTableFrom failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}

	if entries[0].IP != "10.0.0.1" || entries[0].MAC != "aa:bb:cc:dd:ee:01" || entries[0].Interface != "enp1s0.99" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
	// MAC should be lowercased regardless of how the kernel wrote it.
	if entries[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("MAC wasn't normalized to lowercase: %+v", entries[1])
	}
}

func TestReadARPTableSkipsIncompleteAndEmptyEntries(t *testing.T) {
	fixture := `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.5         0x1         0x0         00:00:00:00:00:00     *        enp1s0.99
10.0.0.6         0x1         0x2         00:00:00:00:00:00     *        enp1s0.99
10.0.0.7         0x1         0x2         aa:bb:cc:dd:ee:03     *        enp1s0.99
`
	entries, err := readARPTableFrom(writeFixture(t, fixture))
	if err != nil {
		t.Fatalf("readARPTableFrom failed: %v", err)
	}
	// Only the third line is a genuinely resolved, non-zero entry -
	// the first is flagged incomplete (0x0), the second has the flag
	// but an all-zero MAC (shouldn't happen in practice, but a real
	// parser needs to be defensive about it anyway).
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(entries), entries)
	}
	if entries[0].IP != "10.0.0.7" {
		t.Fatalf("unexpected surviving entry: %+v", entries[0])
	}
}

func TestReadARPTableHandlesMalformedLinesGracefully(t *testing.T) {
	fixture := `IP address       HW type     Flags       HW address            Mask     Device
not enough fields
10.0.0.8         0x1         0x2         aa:bb:cc:dd:ee:04     *        enp1s0.99
`
	entries, err := readARPTableFrom(writeFixture(t, fixture))
	if err != nil {
		t.Fatalf("readARPTableFrom failed: %v", err)
	}
	if len(entries) != 1 || entries[0].IP != "10.0.0.8" {
		t.Fatalf("expected the malformed line to be skipped, not error out: %+v", entries)
	}
}

func TestReadARPTableMissingFile(t *testing.T) {
	if _, err := readARPTableFrom("/nonexistent/path/arp"); err == nil {
		t.Fatal("expected an error for a nonexistent file, got nil")
	}
}

// TestReadARPTableAgainstRealProc is a light sanity check against
// whatever this machine's actual /proc/net/arp looks like right now -
// not asserting specific content (that varies by environment), just
// that the real kernel-provided format parses without error.
func TestReadARPTableAgainstRealProc(t *testing.T) {
	if _, err := os.Stat("/proc/net/arp"); err != nil {
		t.Skip("no /proc/net/arp on this system")
	}
	entries, err := ReadARPTable()
	if err != nil {
		t.Fatalf("ReadARPTable against the real /proc/net/arp failed: %v", err)
	}
	t.Logf("parsed %d real ARP entries", len(entries))
}
