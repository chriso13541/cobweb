// Package status is a small in-memory, concurrency-safe place for the
// DHCP and DNS servers to report whether they're actually up, so a
// failure in either one (e.g. a bad interface name) never has to take
// down the whole process to be visible - it shows up on the dashboard
// instead.
package status

import "sync"

// State is a snapshot of one service's health.
type State struct {
	Up      bool
	LastErr string
}

var (
	mu   sync.RWMutex
	dhcp State
	dns  State
)

// SetDHCP updates the DHCP server's reported state.
func SetDHCP(up bool, err error) {
	mu.Lock()
	defer mu.Unlock()
	dhcp.Up = up
	if err != nil {
		dhcp.LastErr = err.Error()
	} else {
		dhcp.LastErr = ""
	}
}

// SetDNS updates the DNS server's reported state.
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

// Snapshot returns the current state of both services.
func Snapshot() (dhcpState, dnsState State) {
	mu.RLock()
	defer mu.RUnlock()
	return dhcp, dns
}
