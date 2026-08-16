// Package config is the single source of truth for cobweb's runtime
// settings. It's loaded from and persisted to one JSON file, and is safe
// for concurrent access: the DHCP and DNS servers read it on every
// request, while the web UI writes to it when the person changes a
// setting. There is deliberately no other config file anywhere else on
// the system — this replaces dnsmasq.conf, the netplan static-lease
// workarounds, and hand-edited hosts files with one place to look.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// LANSegment is one routed LAN - in practice, usually one VLAN with its
// own 802.1q subinterface (e.g. enp1s0.20), its own subnet, and its own
// DHCP pool. cobweb runs one DHCP listener per segment, all sharing the
// same reservation/lease/DNS-override data (each entry just records
// which segment it belongs to).
type LANSegment struct {
	ID         string `json:"id"`          // stable, immutable - generated once, never changes even if Name/Interface do
	Name       string `json:"name"`        // display label, e.g. "Trusted", "IoT", "Guest"
	Interface  string `json:"interface"`   // e.g. "enp1s0" for a flat LAN, or "enp1s0.20" for a VLAN subinterface
	Address    string `json:"address"`     // this segment's own gateway IP, e.g. 192.168.20.1
	SubnetMask string `json:"subnet_mask"` // e.g. 255.255.255.0
	PoolStart  string `json:"pool_start"`
	PoolEnd    string `json:"pool_end"`
	Domain     string `json:"domain"` // local DNS suffix for this segment, e.g. "lan"
	// DHCPDisabled opts a segment OUT of DHCP - deliberately named for
	// the rare case (most segments want DHCP) rather than
	// DHCPEnabled, so the Go zero value (false) means "DHCP on" for
	// every segment that predates this field, with no migration
	// needed. Meant for a segment that's purely static IPs (e.g. a
	// switch management VLAN) with no dynamic clients ever expected.
	DHCPDisabled bool `json:"dhcp_disabled"`
}

// Reservation pins a specific MAC address to a specific IP address,
// permanently, regardless of the dynamic pool. This is the equivalent of
// a router's "DHCP reservation" feature.
type Reservation struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	SegmentID string `json:"segment_id"` // which LANSegment this reservation belongs to
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
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
	SegmentID string `json:"segment_id"` // which LANSegment this lease was allocated from
}

// DiscoveredDevice is a device cobweb has observed via the live ARP
// table but never DHCP-served - e.g. something with a manually
// assigned static IP. Persisted (unlike the ARP table itself, which
// only reflects what the kernel currently has cached) so it keeps
// showing up even after the device goes quiet long enough for its
// ARP entry to age out - the same way a DHCP lease stays listed and
// shows "expired" rather than disappearing outright.
type DiscoveredDevice struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	SegmentID string `json:"segment_id"`
	LastSeen  int64  `json:"last_seen"` // unix seconds, refreshed every time this MAC still shows up live in ARP
}

// Config holds every setting cobweb needs across its DHCP server, DNS
// server, and web dashboard.
type Config struct {
	// Interfaces
	WANInterface string       `json:"wan_interface"`
	LANSegments  []LANSegment `json:"lan_segments"`

	// DHCP (shared across all segments)
	LeaseSeconds int `json:"lease_seconds"` // default lease duration

	// DNS (one shared resolver regardless of which segment a query
	// comes from - see the design note in dnsserver's package doc)
	DNSMode         string   `json:"dns_mode"`         // "forward" (default) or "recursive"
	UpstreamServers []string `json:"upstream_servers"` // e.g. ["1.1.1.1:53", "9.9.9.9:53"] - used when dns_mode is "forward"

	// Dashboard
	ListenAddr string `json:"listen_addr"`

	// Data
	Reservations      []Reservation      `json:"reservations"`
	DNSRecords        []DNSRecord        `json:"dns_records"`
	Leases            []Lease            `json:"leases"`
	DiscoveredDevices []DiscoveredDevice `json:"discovered_devices"`
	HostnameOverrides map[string]string  `json:"hostname_overrides"` // MAC -> user-assigned name, takes priority over whatever DHCP reports

	path string       // where this config was loaded from / saves to
	mu   sync.RWMutex // guards all fields above during concurrent access
}

// legacyFields captures the pre-VLAN single-LAN shape, used only to
// migrate an old config.json (which has these keys at the top level
// instead of inside lan_segments) the first time it's loaded after
// upgrading.
type legacyFields struct {
	LANInterface string `json:"lan_interface"`
	LANAddress   string `json:"lan_address"`
	SubnetMask   string `json:"subnet_mask"`
	PoolStart    string `json:"pool_start"`
	PoolEnd      string `json:"pool_end"`
	Domain       string `json:"domain"`
}

// newSegmentID generates a short, random, stable identifier for a new
// LANSegment - deliberately independent of Name or Interface, since
// both of those can be edited later without breaking whichever DHCP
// listener goroutine is tracking this segment.
func newSegmentID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is essentially unheard of on Linux, but
		// fall back to something still unique-enough rather than panic.
		return "seg-fallback"
	}
	return "seg-" + hex.EncodeToString(b)
}

// Default returns a Config populated with sane starting values,
// including exactly one LAN segment matching what a fresh install
// used before VLAN support existed - so a brand-new install still
// works immediately without requiring Settings configuration first.
func Default(path string) *Config {
	return &Config{
		WANInterface: "wlp2s0",
		LANSegments: []LANSegment{
			{
				ID:         newSegmentID(),
				Name:       "Default",
				Interface:  "enp1s0",
				Address:    "192.168.2.1",
				SubnetMask: "255.255.255.0",
				PoolStart:  "192.168.2.10",
				PoolEnd:    "192.168.2.254",
				Domain:     "lan",
			},
		},
		LeaseSeconds:      86400,
		DNSMode:           "forward",
		UpstreamServers:   []string{"1.1.1.1:53", "9.9.9.9:53"},
		ListenAddr:        "0.0.0.0:8070",
		Reservations:      []Reservation{},
		DNSRecords:        []DNSRecord{},
		Leases:            []Lease{},
		DiscoveredDevices: []DiscoveredDevice{},
		HostnameOverrides: map[string]string{},
		path:              path,
	}
}

// Load reads config from path, or returns a fresh Default config (not
// yet saved to disk) if the file doesn't exist yet. Automatically
// migrates an older single-LAN config.json into a one-segment
// LANSegments list the first time it's loaded after upgrading.
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
	if c.HostnameOverrides == nil {
		c.HostnameOverrides = map[string]string{} // older config files predate this field
	}

	if len(c.LANSegments) == 0 {
		var legacy legacyFields
		// Only the old top-level keys matter here; ignore anything else.
		if err := json.Unmarshal(b, &legacy); err == nil && legacy.LANInterface != "" {
			domain := legacy.Domain
			if domain == "" {
				domain = "lan"
			}
			seg := LANSegment{
				ID:         newSegmentID(),
				Name:       "Default",
				Interface:  legacy.LANInterface,
				Address:    legacy.LANAddress,
				SubnetMask: legacy.SubnetMask,
				PoolStart:  legacy.PoolStart,
				PoolEnd:    legacy.PoolEnd,
				Domain:     domain,
			}
			c.LANSegments = []LANSegment{seg}
			// Tag any pre-existing leases/reservations (which predate
			// segments entirely, so have no SegmentID yet) as
			// belonging to this migrated segment.
			for i := range c.Reservations {
				if c.Reservations[i].SegmentID == "" {
					c.Reservations[i].SegmentID = seg.ID
				}
			}
			for i := range c.Leases {
				if c.Leases[i].SegmentID == "" {
					c.Leases[i].SegmentID = seg.ID
				}
			}
			// Persist the migration immediately so it only ever runs
			// once. Safe to call saveLocked directly without taking
			// the lock here - this *Config hasn't been shared with
			// any other goroutine yet at this point in Load.
			if err := c.saveLocked(); err != nil {
				return nil, fmt.Errorf("persist migrated config: %w", err)
			}
		}
	}

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
	WANInterface      string
	LANSegments       []LANSegment
	LeaseSeconds      int
	DNSMode           string
	UpstreamServers   []string
	ListenAddr        string
	Reservations      []Reservation
	DNSRecords        []DNSRecord
	Leases            []Lease
	DiscoveredDevices []DiscoveredDevice
	HostnameOverrides map[string]string
}

// Snapshot returns a value copy of the config's data fields, safe to
// read without holding the lock further (e.g. for rendering a settings
// page).
func (c *Config) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Snapshot{
		WANInterface:      c.WANInterface,
		LANSegments:       append([]LANSegment{}, c.LANSegments...),
		LeaseSeconds:      c.LeaseSeconds,
		DNSMode:           c.DNSMode,
		UpstreamServers:   append([]string{}, c.UpstreamServers...),
		ListenAddr:        c.ListenAddr,
		Reservations:      append([]Reservation{}, c.Reservations...),
		DNSRecords:        append([]DNSRecord{}, c.DNSRecords...),
		Leases:            append([]Lease{}, c.Leases...),
		DiscoveredDevices: append([]DiscoveredDevice{}, c.DiscoveredDevices...),
		HostnameOverrides: copyStringMap(c.HostnameOverrides),
	}
}

func copyStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SegmentByID returns the segment with the given ID, if it still
// exists (it may have been removed via Settings since whatever code
// called this last looked it up).
func (c *Config) SegmentByID(id string) (LANSegment, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.LANSegments {
		if s.ID == id {
			return s, true
		}
	}
	return LANSegment{}, false
}

// AddLANSegment adds a new VLAN/LAN segment. Its ID is generated here,
// ignoring anything the caller supplied, since IDs must be unique and
// immutable for the lifetime of the segment.
func (c *Config) AddLANSegment(seg LANSegment) (LANSegment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seg.ID = newSegmentID()
	c.LANSegments = append(c.LANSegments, seg)
	return seg, c.saveLocked()
}

// UpdateLANSegment updates an existing segment's editable fields
// (Name, Interface, Address, SubnetMask, PoolStart, PoolEnd, Domain),
// keyed by its immutable ID.
func (c *Config) UpdateLANSegment(id string, updated LANSegment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, s := range c.LANSegments {
		if s.ID == id {
			updated.ID = id // ID itself is never editable
			c.LANSegments[i] = updated
			return c.saveLocked()
		}
	}
	return fmt.Errorf("segment %q not found", id)
}

// RemoveLANSegment deletes a segment. Any reservations/leases that
// belonged to it are left in place (they'll just show an unresolved
// segment reference) rather than silently deleted, since a person
// might remove a segment by mistake and want their reservations back
// after re-adding it.
func (c *Config) RemoveLANSegment(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.LANSegments[:0]
	for _, s := range c.LANSegments {
		if s.ID != id {
			out = append(out, s)
		}
	}
	c.LANSegments = out
	return c.saveLocked()
}

// ReservationForMAC returns the static reservation for a MAC address, if
// one exists. MAC addresses are globally unique, so this doesn't need
// to know which segment to look in.
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

// SetHostnameOverride assigns a user-chosen display name to a MAC
// address, taking priority over whatever hostname DHCP reports for it
// from now on. Passing an empty hostname clears the override, letting
// the DHCP-reported name (or "(unknown)" if the device never sends
// one) show through again. This exists specifically because a plain
// edit to a dynamic lease's Hostname field would just get overwritten
// on the device's next DHCP renewal - the override is a separate,
// durable layer on top of that.
func (c *Config) SetHostnameOverride(mac, hostname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.HostnameOverrides == nil {
		c.HostnameOverrides = map[string]string{}
	}
	if hostname == "" {
		delete(c.HostnameOverrides, mac)
	} else {
		c.HostnameOverrides[mac] = hostname
	}
	return c.saveLocked()
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

// RemoveLease deletes a dynamic lease entry by MAC. Note this only
// clears it from cobweb's records - if the device is still actually
// on the network, it'll simply get a fresh lease (possibly the same
// IP) the next time it renews. This is for clearing stale/known
// entries from view, not for blocking a device - that's a separate,
// not-yet-built feature.
func (c *Config) RemoveLease(mac string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.Leases[:0]
	for _, l := range c.Leases {
		if l.MAC != mac {
			out = append(out, l)
		}
	}
	c.Leases = out
	return c.saveLocked()
}

// UpsertDiscoveredDevice records or refreshes a device seen via the
// live ARP table but never DHCP-served. Called every time the
// devices list is rendered and a MAC shows up in ARP that isn't
// already covered by a lease or reservation - refreshing LastSeen
// keeps the record current without ever needing the ARP entry itself
// to still exist.
func (c *Config) UpsertDiscoveredDevice(d DiscoveredDevice) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, existing := range c.DiscoveredDevices {
		if existing.MAC == d.MAC {
			c.DiscoveredDevices[i] = d
			return c.saveLocked()
		}
	}
	c.DiscoveredDevices = append(c.DiscoveredDevices, d)
	return c.saveLocked()
}

// RemoveDiscoveredDevice deletes a discovered-device record by MAC.
// If that device is still actually live on the network, it'll simply
// get re-added the next time its ARP entry is observed - this is for
// clearing something you don't want cluttering the list, not for
// blocking a device.
func (c *Config) RemoveDiscoveredDevice(mac string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.DiscoveredDevices[:0]
	for _, d := range c.DiscoveredDevices {
		if d.MAC != mac {
			out = append(out, d)
		}
	}
	c.DiscoveredDevices = out
	return c.saveLocked()
}

// IPInUse reports whether ip is currently held by any active lease or
// reservation other than excludeMAC. Used by the pool allocator to
// avoid double-assigning an address. Deliberately checks across all
// segments, not just the caller's own one - a plain safety net against
// two segments' subnets accidentally overlapping.
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

// UpdateGlobalNetwork applies the settings that apply across every
// segment at once: the WAN interface, DHCP lease duration, and DNS
// mode/upstream servers. Per-segment settings (interface, subnet,
// pool, domain) go through AddLANSegment/UpdateLANSegment instead.
func (c *Config) UpdateGlobalNetwork(wan, dnsMode string, leaseSeconds int, upstream []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.WANInterface = wan
	c.DNSMode = dnsMode
	c.LeaseSeconds = leaseSeconds
	c.UpstreamServers = upstream
	return c.saveLocked()
}

// ParsePoolRangeForSegment returns the start and end of a segment's
// dynamic pool as 4-byte IPs, for the allocator to iterate over.
func (c *Config) ParsePoolRangeForSegment(segmentID string) (net.IP, net.IP, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.LANSegments {
		if s.ID != segmentID {
			continue
		}
		start := net.ParseIP(s.PoolStart).To4()
		end := net.ParseIP(s.PoolEnd).To4()
		if start == nil || end == nil {
			return nil, nil, fmt.Errorf("segment %q: invalid pool range %q - %q", s.Name, s.PoolStart, s.PoolEnd)
		}
		return start, end, nil
	}
	return nil, nil, fmt.Errorf("segment %q not found", segmentID)
}
