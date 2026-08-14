package netstat

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// ARPEntry is one resolved (not pending) entry from the kernel's ARP
// table for a given interface.
type ARPEntry struct {
	IP        string
	MAC       string
	Interface string
}

// ATF_COMPLETE, from <linux/if_arp.h> - the flags bit meaning this
// entry has actually been resolved to a MAC address, as opposed to a
// pending/incomplete resolution still in progress.
const atfComplete = 0x2

// ReadARPTable parses /proc/net/arp and returns every complete
// (resolved) entry. This is passive: it only reflects devices the
// kernel has actually exchanged a packet with at some point (a DHCP
// client, something pinged, a device that sent unsolicited traffic,
// etc.) - not an active scan of everything possibly present on a
// subnet. That's deliberate: it costs zero extra network traffic and
// needs no privileges beyond reading a file the kernel already
// maintains, at the cost of only surfacing devices cobweb has some
// actual reason to know about already.
func ReadARPTable() ([]ARPEntry, error) {
	return readARPTableFrom("/proc/net/arp")
}

func readARPTableFrom(path string) ([]ARPEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []ARPEntry
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // header line: "IP address  HW type  Flags  HW address  Mask  Device"
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		ip, flagsStr, mac, device := fields[0], fields[2], fields[3], fields[5]

		flags, err := strconv.ParseInt(strings.TrimPrefix(flagsStr, "0x"), 16, 64)
		if err != nil || flags&atfComplete == 0 {
			continue // still resolving, or otherwise not a usable entry
		}
		if mac == "00:00:00:00:00:00" {
			continue
		}

		entries = append(entries, ARPEntry{
			IP:        ip,
			MAC:       strings.ToLower(mac),
			Interface: device,
		})
	}
	return entries, scanner.Err()
}
