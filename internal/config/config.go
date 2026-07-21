// Package config is the single source of truth for cobweb's runtime
// settings. It's loaded from and persisted to one JSON file, and is safe
// for concurrent access: the DHCP and DNS servers read it on every
// request, while the web UI writes to it when the person changes a
// setting. There is deliberately no other config file anywhere else on
// the system — this replaces dnsmasq.conf, the netplan static-lease
// workarounds, and hand-edited hosts files with one place to look.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// Reservation pins a specific MAC address to a specific IP address,
// permanently, regardless of the dynamic pool. This is the equivalent of
// a router's "DHCP reservation" feature.
type Reservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// DNSRecord is a manually-defined local DNS entry, independent of
// whatever DHCP has leased. Useful for pointing a name at something that
// isn't a DHCP client at all (e.g. a service running on the gateway
// itself).
type DNSRecord struct {
	Name string `json:"name"` // e.g. "nas.lan"
	IP   string `json:"ip"`
}

// Lease is a dynamically-assigned, non-reserved address handed out from
// the pool. Persisted so leases survive a cobweb restart.
type Lease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

// Config holds every setting cobweb needs across its DHCP server, DNS
// server, and web dashboard.
type Config struct {
	// Interfaces
	WANInterface string `json:"wan_interface"`
	LANInterface string `json:"lan_interface"`

	// Network
	LANAddress   string `json:"lan_address"`   // this box's own address on the LAN, e.g. 192.168.2.1
	SubnetMask   string `json:"subnet_mask"`   // e.g. 255.255.255.0
	PoolStart    string `json:"pool_start"`    // e.g. 192.168.2.10
	PoolEnd      string `json:"pool_end"`      // e.g. 192.168.2.254
	LeaseSeconds int    `json:"lease_seconds"` // default lease duration

	// DNS
	Domain          string   `json:"domain"`           // local suffix, e.g. "lan"
	UpstreamServers []string `json:"upstream_servers"` // e.g. ["1.1.1.1:53", "9.9.9.9:53"]

	// Dashboard
	ListenAddr string `json:"listen_addr"`

	// Data
	Reservations []Reservation `json:"reservations"`
	DNSRecords   []DNSRecord   `json:"dns_records"`
	Leases       []Lease       `json:"leases"`

	path string       // where this config was loaded from / saves to
	mu   sync.RWMutex // guards all fields above during concurrent access
}

// Default returns a Config populated with sane starting values. Used
// when no config file exists yet (first run).
func Default(path string) *Config {
	return &Config{
		WANInterface:    "wlp2s0",
		LANInterface:    "enp1s0",
		LANAddress:      "192.168.2.1",
		SubnetMask:      "255.255.255.0",
		PoolStart:       "192.168.2.10",
		PoolEnd:         "192.168.2.254",
		LeaseSeconds:    86400,
		Domain:          "lan",
		UpstreamServers: []string{"1.1.1.1:53", "9.9.9.9:53"},
		ListenAddr:      "0.0.0.0:8070",
		Reservations:    []Reservation{},
		DNSRecords:      []DNSRecord{},
		Leases:          []Lease{},
		path:            path,
	}
}

// Load reads config from path, or returns a fresh Default config (not
// yet saved to disk) if the file doesn't exist yet.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(path), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.path = path
	return c, nil
}

// Save persists the current config to disk as JSON.
func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.saveLocked()
}

// saveLocked writes to disk assuming the caller already holds a lock.
func (c *Config) saveLocked() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	// Atomic rename so a crash mid-write never leaves a half-written
	// config file that fails to parse on next boot.
	return os.Rename(tmp, c.path)
}

// Snapshot is a plain, mutex-free copy of Config's data fields. Unlike
// Config itself, it's safe to pass around by value - to templates,
// across goroutines, wherever - since it holds no lock. This is
// deliberately a distinct type from Config (not just Config with the
// mutex zeroed out): go vet flags copying *any* value of a type that
// embeds sync.RWMutex, even a freshly-built one, so a separate type is
// the clean way to hand out read-only data.
type Snapshot struct {
	WANInterface    string
	LANInterface    string
	LANAddress      string
	SubnetMask      string
	PoolStart       string
	PoolEnd         string
	LeaseSeconds    int
	Domain          string
	UpstreamServers []string
	ListenAddr      string
	Reservations    []Reservation
	DNSRecords      []DNSRecord
	Leases          []Lease
}

// Snapshot returns a value copy of the config's data fields, safe to
// read without holding the lock further (e.g. for rendering a settings
// page).
func (c *Config) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Snapshot{
		WANInterface:    c.WANInterface,
		LANInterface:    c.LANInterface,
		LANAddress:      c.LANAddress,
		SubnetMask:      c.SubnetMask,
		PoolStart:       c.PoolStart,
		PoolEnd:         c.PoolEnd,
		LeaseSeconds:    c.LeaseSeconds,
		Domain:          c.Domain,
		UpstreamServers: append([]string{}, c.UpstreamServers...),
		ListenAddr:      c.ListenAddr,
		Reservations:    append([]Reservation{}, c.Reservations...),
		DNSRecords:      append([]DNSRecord{}, c.DNSRecords...),
		Leases:          append([]Lease{}, c.Leases...),
	}
}

// ReservationForMAC returns the static reservation for a MAC address, if
// one exists.
func (c *Config) ReservationForMAC(mac string) (Reservation, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.Reservations {
		if r.MAC == mac {
			return r, true
		}
	}
	return Reservation{}, false
}

// AddReservation adds or updates a static MAC->IP reservation and
// persists the change immediately.
func (c *Config) AddReservation(r Reservation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, existing := range c.Reservations {
		if existing.MAC == r.MAC {
			c.Reservations[i] = r
			return c.saveLocked()
		}
	}
	c.Reservations = append(c.Reservations, r)
	return c.saveLocked()
}

// RemoveReservation deletes a reservation by MAC address.
func (c *Config) RemoveReservation(mac string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.Reservations[:0]
	for _, r := range c.Reservations {
		if r.MAC != mac {
			out = append(out, r)
		}
	}
	c.Reservations = out
	return c.saveLocked()
}

// AddDNSRecord adds or updates a manual DNS record and persists it.
func (c *Config) AddDNSRecord(rec DNSRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, existing := range c.DNSRecords {
		if existing.Name == rec.Name {
			c.DNSRecords[i] = rec
			return c.saveLocked()
		}
	}
	c.DNSRecords = append(c.DNSRecords, rec)
	return c.saveLocked()
}

// RemoveDNSRecord deletes a manual DNS record by name.
func (c *Config) RemoveDNSRecord(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.DNSRecords[:0]
	for _, r := range c.DNSRecords {
		if r.Name != name {
			out = append(out, r)
		}
	}
	c.DNSRecords = out
	return c.saveLocked()
}

// UpsertLease records or refreshes a dynamic lease and persists it. This
// is called by the DHCP server on every ACK so leases survive a restart.
func (c *Config) UpsertLease(l Lease) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, existing := range c.Leases {
		if existing.MAC == l.MAC {
			c.Leases[i] = l
			return c.saveLocked()
		}
	}
	c.Leases = append(c.Leases, l)
	return c.saveLocked()
}

// LeaseForMAC returns the current dynamic lease for a MAC, if any.
func (c *Config) LeaseForMAC(mac string) (Lease, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, l := range c.Leases {
		if l.MAC == mac {
			return l, true
		}
	}
	return Lease{}, false
}

// IPInUse reports whether ip is currently held by any active lease or
// reservation other than excludeMAC. Used by the pool allocator to avoid
// double-assigning an address.
func (c *Config) IPInUse(ip string, excludeMAC string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.Reservations {
		if r.IP == ip && r.MAC != excludeMAC {
			return true
		}
	}
	for _, l := range c.Leases {
		if l.IP == ip && l.MAC != excludeMAC {
			return true
		}
	}
	return false
}

// UpdateNetwork applies new network/DHCP/DNS settings from the settings
// page in one atomic write.
func (c *Config) UpdateNetwork(wan, lan, lanAddr, mask, poolStart, poolEnd, domain string, leaseSeconds int, upstream []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.WANInterface = wan
	c.LANInterface = lan
	c.LANAddress = lanAddr
	c.SubnetMask = mask
	c.PoolStart = poolStart
	c.PoolEnd = poolEnd
	c.Domain = domain
	c.LeaseSeconds = leaseSeconds
	c.UpstreamServers = upstream
	return c.saveLocked()
}

// ParsePoolRange returns the start and end of the dynamic pool as
// 4-byte IPs, for the allocator to iterate over.
func (c *Config) ParsePoolRange() (net.IP, net.IP, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	start := net.ParseIP(c.PoolStart).To4()
	end := net.ParseIP(c.PoolEnd).To4()
	if start == nil || end == nil {
		return nil, nil, fmt.Errorf("invalid pool range %q - %q", c.PoolStart, c.PoolEnd)
	}
	return start, end, nil
}
