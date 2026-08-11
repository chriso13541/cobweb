// Package status is a small in-memory, concurrency-safe place for the
// DHCP and DNS servers to report whether they're actually up, so a
// failure in any of them (e.g. a bad interface name) never has to take
// down the whole process to be visible - it shows up on the dashboard
// instead. DHCP is tracked per LAN segment, since a multi-VLAN box
// runs one DHCP listener per segment rather than a single global one;
// DNS stays a single shared state, since there's still just one
// resolver regardless of how many segments exist.
package status

import "sync"

// State is a snapshot of one service's health.
type State struct {
	Up      bool
	LastErr string
}

// DHCPSegmentState is one segment's DHCP listener health, along with
// enough identity to display it without a second lookup.
type DHCPSegmentState struct {
	SegmentID   string
	SegmentName string
	State
}

var (
	mu          sync.RWMutex
	dns         State
	dhcpBySegID = map[string]DHCPSegmentState{}
)

// SetDHCPSegment updates one segment's DHCP listener state.
func SetDHCPSegment(segmentID, segmentName string, up bool, err error) {
	mu.Lock()
	defer mu.Unlock()
	s := DHCPSegmentState{SegmentID: segmentID, SegmentName: segmentName, State: State{Up: up}}
	if err != nil {
		s.LastErr = err.Error()
	}
	dhcpBySegID[segmentID] = s
}

// SetDNS updates the shared DNS server's reported state.
func SetDNS(up bool, err error) {
	mu.Lock()
	defer mu.Unlock()
	dns.Up = up
	if err != nil {
		dns.LastErr = err.Error()
	} else {
		dns.LastErr = ""
	}
}

// DNSState returns the current DNS server state.
func DNSState() State {
	mu.RLock()
	defer mu.RUnlock()
	return dns
}

// DHCPSegmentStates returns the current state of every segment's DHCP
// listener that has reported in at least once, in no particular order
// - callers wanting a stable display order should sort by SegmentName.
func DHCPSegmentStates() []DHCPSegmentState {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]DHCPSegmentState, 0, len(dhcpBySegID))
	for _, s := range dhcpBySegID {
		out = append(out, s)
	}
	return out
}
