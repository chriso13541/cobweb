package web

import (
	"embed"
	"encoding/binary"
	"html/template"
	"log"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"cobweb/internal/auth"
	"cobweb/internal/config"
	"cobweb/internal/dnsserver"
	"cobweb/internal/netstat"
	"cobweb/internal/status"
)

const sessionCookieName = "cobweb_session"

// Server holds shared dependencies for HTTP handlers.
type Server struct {
	cfg      *config.Config
	tmpl     *template.Template
	creds    *auth.Store
	sessions *auth.SessionManager
	throttle *auth.LoginThrottle
}

//go:embed templates/*.html
var templateFS embed.FS

// New constructs a Server with templates parsed and ready to serve.
func New(cfg *config.Config, creds *auth.Store) (*Server, error) {
	funcs := template.FuncMap{
		"join": strings.Join,
		"segmentName": func(segments []config.LANSegment, id string) string {
			return segmentDisplayName(segments, id)
		},
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		tmpl:     tmpl,
		creds:    creds,
		sessions: auth.NewSessionManager(),
		throttle: auth.NewLoginThrottle(),
	}, nil
}

// Routes returns the configured HTTP mux. Every route except /login
// requires a valid session.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/settings", s.requireAuth(s.handleSettingsPage))
	mux.HandleFunc("/diagnostics/arp", s.requireAuth(s.handleARPDiagnostics))
	mux.HandleFunc("/fragments/devices", s.requireAuth(s.handleDevicesFragment))
	mux.HandleFunc("/fragments/interfaces", s.requireAuth(s.handleInterfacesFragment))
	mux.HandleFunc("/fragments/performance", s.requireAuth(s.handlePerformanceFragment))
	mux.HandleFunc("/api/reservations/add", s.requireAuth(s.handleAddReservation))
	mux.HandleFunc("/api/reservations/remove", s.requireAuth(s.handleRemoveReservation))
	mux.HandleFunc("/api/reservations/quickadd", s.requireAuth(s.handleQuickReserve))
	mux.HandleFunc("/api/reservations/quickremove", s.requireAuth(s.handleQuickRemoveReservation))
	mux.HandleFunc("/api/leases/quickremove", s.requireAuth(s.handleQuickRemoveLease))
	mux.HandleFunc("/api/devices/rename", s.requireAuth(s.handleRenameDevice))
	mux.HandleFunc("/api/dns/add", s.requireAuth(s.handleAddDNSRecord))
	mux.HandleFunc("/api/dns/remove", s.requireAuth(s.handleRemoveDNSRecord))
	mux.HandleFunc("/api/network/update", s.requireAuth(s.handleUpdateNetwork))
	mux.HandleFunc("/api/segments/add", s.requireAuth(s.handleAddLANSegment))
	mux.HandleFunc("/api/segments/update", s.requireAuth(s.handleUpdateLANSegment))
	mux.HandleFunc("/api/segments/remove", s.requireAuth(s.handleRemoveLANSegment))
	mux.HandleFunc("/api/account/update", s.requireAuth(s.handleAccountUpdate))

	return mux
}

// --- auth ---

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !s.sessions.Valid(cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// handleLogin serves the login form on GET and processes credentials
// on POST. Combining both in one handler keeps the route table simple
// and matches the pattern the rest of this file already uses.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if cookie, err := r.Cookie(sessionCookieName); err == nil && s.sessions.Valid(cookie.Value) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		data := struct{ Error bool }{Error: r.URL.Query().Get("error") == "1"}
		if err := s.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
			log.Printf("render login: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Throttle before checking credentials, so the delay applies
	// consistently regardless of whether this attempt succeeds.
	if d := s.throttle.Delay(); d > 0 {
		time.Sleep(d)
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if !s.creds.Verify(username, password) {
		s.throttle.RecordFailure()
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	s.throttle.RecordSuccess()

	token, err := s.sessions.Create()
	if err != nil {
		log.Printf("create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.Revoke(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- pages ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := struct {
		LANSegments []config.LANSegment
	}{LANSegments: s.cfg.Snapshot().LANSegments}
	if err := s.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("render dashboard: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// settingsData wraps a config snapshot with page-local flash state
// (e.g. an account-settings error) that isn't part of persisted
// config.
type settingsData struct {
	config.Snapshot
	AccountError   string
	AccountSuccess string
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "", "")
}

// arpDiagRow is one raw ARP table entry, annotated with whether it
// matched a configured LAN segment - built specifically to answer
// "why isn't this device showing up" without needing to guess at
// internals or read source code. A mismatch here (an interface string
// in /proc/net/arp that doesn't match any configured segment's
// Interface field exactly) is the most common real cause.
type arpDiagRow struct {
	IP          string
	MAC         string
	Interface   string
	MatchedName string // segment name if matched, else ""
	Matched     bool
}

func (s *Server) handleARPDiagnostics(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()
	segmentByInterface := map[string]string{}
	for _, seg := range snap.LANSegments {
		segmentByInterface[seg.Interface] = seg.Name
	}

	entries, err := netstat.ReadARPTable()
	var readErr string
	if err != nil {
		readErr = err.Error()
	}

	rows := make([]arpDiagRow, 0, len(entries))
	for _, e := range entries {
		name, ok := segmentByInterface[e.Interface]
		rows = append(rows, arpDiagRow{
			IP:          e.IP,
			MAC:         e.MAC,
			Interface:   e.Interface,
			MatchedName: name,
			Matched:     ok,
		})
	}

	configuredIfaces := make([]string, 0, len(snap.LANSegments))
	for _, seg := range snap.LANSegments {
		configuredIfaces = append(configuredIfaces, seg.Interface)
	}

	data := struct {
		Rows             []arpDiagRow
		ReadErr          string
		ConfiguredIfaces []string
	}{Rows: rows, ReadErr: readErr, ConfiguredIfaces: configuredIfaces}

	if err := s.tmpl.ExecuteTemplate(w, "arp_diagnostics.html", data); err != nil {
		log.Printf("render arp diagnostics: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, accountErr, accountOK string) {
	data := settingsData{
		Snapshot:       s.cfg.Snapshot(),
		AccountError:   accountErr,
		AccountSuccess: accountOK,
	}
	if err := s.tmpl.ExecuteTemplate(w, "settings.html", data); err != nil {
		log.Printf("render settings: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// --- fragments ---

// deviceRow is one row of the dashboard's device table, combining
// static reservations and dynamic leases into a single sortable,
// searchable list.
type deviceRow struct {
	RowID           string
	Hostname        string
	IP              string
	MAC             string
	Status          string // "reserved", "active", "expired", "discovered"
	TimeLeft        string
	ExpiresAbsolute string
	Reserved        bool
	Discovered      bool   // sourced from the ARP table, not a DHCP lease or reservation - nothing persisted to remove
	Editing         bool   // whether this row is currently showing the rename form
	Segment         string // display name of the LAN segment this device is on
	SegmentID       string // raw segment ID, for quick-action forms that need to preserve it
}

// resolveHostname applies the priority order for what name to show for
// a device: a user-set override always wins (it exists specifically to
// survive DHCP renewals overwriting it), then whatever hostname was
// actually reported (by DHCP or a reservation), then a fallback for
// devices that never report one at all.
func resolveHostname(overrides map[string]string, mac, reported string) string {
	if override, ok := overrides[mac]; ok && override != "" {
		return override
	}
	if reported == "" {
		return "(unknown)"
	}
	return reported
}

// segmentDisplayName looks up a segment's Name by ID from a snapshot's
// LANSegments, falling back to something sensible if the segment no
// longer exists (e.g. it was removed via Settings after this entry
// was created).
func segmentDisplayName(segments []config.LANSegment, segmentID string) string {
	for _, s := range segments {
		if s.ID == segmentID {
			return s.Name
		}
	}
	if segmentID == "" {
		return "—"
	}
	return "(removed)"
}

// handleDevicesFragment returns the device list body, built from
// current DHCP leases and static reservations - both live in cobweb's
// own config now, no external lease file to parse. Supports optional
// ?q=, ?sort=, ?dir= query params for search and sorting, and an
// "editing" param (comma-separated row IDs) so the dashboard's
// periodic refresh can tell the server which rows should render their
// rename form instead of the plain hostname - baking that into the
// initial HTML, rather than rendering plain and correcting it
// client-side after the fact, is what avoids a mid-edit row getting
// silently reset by the next refresh.
func (s *Server) handleDevicesFragment(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()
	now := time.Now()

	editingIDs := map[string]bool{}
	for _, id := range strings.Split(r.FormValue("editing"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			editingIDs[id] = true
		}
	}

	var rows []deviceRow
	seen := map[string]bool{}

	for _, res := range snap.Reservations {
		id := rowID(res.MAC)
		rows = append(rows, deviceRow{
			RowID:           id,
			Hostname:        resolveHostname(snap.HostnameOverrides, res.MAC, res.Hostname),
			IP:              res.IP,
			MAC:             res.MAC,
			Status:          "reserved",
			TimeLeft:        "static",
			ExpiresAbsolute: "Permanent (static reservation)",
			Reserved:        true,
			Editing:         editingIDs[id],
			Segment:         segmentDisplayName(snap.LANSegments, res.SegmentID),
			SegmentID:       res.SegmentID,
		})
		seen[res.MAC] = true
	}

	for _, l := range snap.Leases {
		if seen[l.MAC] {
			continue // already shown as a reservation above
		}
		expires := time.Unix(l.ExpiresAt, 0)
		st := "active"
		if expires.Before(now) {
			st = "expired"
		}
		id := rowID(l.MAC)
		rows = append(rows, deviceRow{
			RowID:           id,
			Hostname:        resolveHostname(snap.HostnameOverrides, l.MAC, l.Hostname),
			IP:              l.IP,
			MAC:             l.MAC,
			Status:          st,
			TimeLeft:        formatTimeLeft(expires, now),
			ExpiresAbsolute: expires.Format("Jan 2, 3:04 PM"),
			Reserved:        false,
			Editing:         editingIDs[id],
			Segment:         segmentDisplayName(snap.LANSegments, l.SegmentID),
			SegmentID:       l.SegmentID,
		})
		seen[l.MAC] = true
	}

	// ARP-discovered devices: anything cobweb has exchanged traffic
	// with but never DHCP-served, e.g. a switch or other device with
	// a manually-assigned static IP. Passive only (see
	// netstat.ReadARPTable's doc comment) - this surfaces a device
	// cobweb already has some reason to know about, not everything
	// possibly present on the subnet.
	segmentByInterface := map[string]config.LANSegment{}
	for _, seg := range snap.LANSegments {
		segmentByInterface[seg.Interface] = seg
	}
	if arpEntries, err := netstat.ReadARPTable(); err != nil {
		log.Printf("read arp table: %v", err)
	} else {
		for _, entry := range arpEntries {
			if seen[entry.MAC] {
				continue
			}
			seg, ok := segmentByInterface[entry.Interface]
			if !ok {
				continue // not on an interface cobweb manages as a LAN segment (e.g. the WAN link) - not relevant here
			}
			id := rowID(entry.MAC)
			rows = append(rows, deviceRow{
				RowID:           id,
				Hostname:        resolveHostname(snap.HostnameOverrides, entry.MAC, ""),
				IP:              entry.IP,
				MAC:             entry.MAC,
				Status:          "discovered",
				ExpiresAbsolute: "Discovered via ARP - not DHCP-tracked",
				Reserved:        false,
				Discovered:      true,
				Editing:         editingIDs[id],
				Segment:         seg.Name,
				SegmentID:       seg.ID,
			})
			seen[entry.MAC] = true
		}
	}

	segmentFilter := strings.TrimSpace(r.URL.Query().Get("segment"))
	if segmentFilter != "" && segmentFilter != "all" {
		filtered := rows[:0:0]
		for _, row := range rows {
			if row.SegmentID == segmentFilter {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if q != "" {
		filtered := rows[:0:0]
		for _, row := range rows {
			hay := strings.ToLower(row.Hostname + " " + row.IP + " " + row.MAC)
			if strings.Contains(hay, q) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}

	sortField := r.URL.Query().Get("sort")
	if sortField == "" {
		sortField = "hostname"
	}
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		dir = "asc"
	}
	sort.SliceStable(rows, func(i, j int) bool {
		var less bool
		switch sortField {
		case "ip":
			less = ipSortKey(rows[i].IP) < ipSortKey(rows[j].IP)
		case "status":
			less = rows[i].Status < rows[j].Status
		default:
			less = strings.ToLower(rows[i].Hostname) < strings.ToLower(rows[j].Hostname)
		}
		if dir == "desc" {
			return !less
		}
		return less
	})

	data := struct {
		Rows  []deviceRow
		Sort  string
		Dir   string
		Query string
	}{Rows: rows, Sort: sortField, Dir: dir, Query: r.URL.Query().Get("q")}

	if err := s.tmpl.ExecuteTemplate(w, "devices_fragment.html", data); err != nil {
		log.Printf("render devices fragment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// segmentPanel is one LAN segment's interface stats + DHCP status, for
// the interfaces panel - one of these per configured VLAN.
type segmentPanel struct {
	Name         string
	Iface        netstat.Interface
	Rx, Tx       string
	DHCPUp       bool
	DHCPErr      string
	DHCPDisabled bool
}

func (s *Server) handleInterfacesFragment(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()

	wan, err := netstat.Stat(snap.WANInterface)
	if err != nil {
		log.Printf("stat wan interface %s: %v", snap.WANInterface, err)
	}

	dhcpBySegment := map[string]status.DHCPSegmentState{}
	for _, st := range status.DHCPSegmentStates() {
		dhcpBySegment[st.SegmentID] = st
	}

	segments := make([]segmentPanel, 0, len(snap.LANSegments))
	for _, seg := range snap.LANSegments {
		iface, err := netstat.Stat(seg.Interface)
		if err != nil {
			log.Printf("stat lan interface %s (%s): %v", seg.Interface, seg.Name, err)
		}
		dhcp := dhcpBySegment[seg.ID]
		segments = append(segments, segmentPanel{
			Name:         seg.Name,
			Iface:        iface,
			Rx:           netstat.HumanBytes(iface.RxBytes),
			Tx:           netstat.HumanBytes(iface.TxBytes),
			DHCPUp:       dhcp.Up,
			DHCPErr:      dhcp.LastErr,
			DHCPDisabled: seg.DHCPDisabled,
		})
	}

	dnsState := status.DNSState()

	data := struct {
		WAN          netstat.Interface
		WANRx, WANTx string
		DNSUp        bool
		DNSErr       string
		Segments     []segmentPanel
	}{
		WAN:      wan,
		WANRx:    netstat.HumanBytes(wan.RxBytes),
		WANTx:    netstat.HumanBytes(wan.TxBytes),
		DNSUp:    dnsState.Up,
		DNSErr:   dnsState.LastErr,
		Segments: segments,
	}

	if err := s.tmpl.ExecuteTemplate(w, "interfaces_fragment.html", data); err != nil {
		log.Printf("render interfaces fragment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handlePerformanceFragment answers the "is this actually using RAM
// well / going as fast as it can" question with the numbers that
// genuinely reflect that for a single flat home network: the DNS
// resolver cache's size and hit rate, the kernel's live NAT
// connection-tracking table (conntrack), and cobweb's own process
// memory. There's no meaningful "routing table" to visualize here -
// that concept applies to multi-router networks exchanging routes
// (BGP/OSPF), not a single gateway with one static default route.
func (s *Server) handlePerformanceFragment(w http.ResponseWriter, r *http.Request) {
	cacheEntries, cacheHits, cacheMisses := dnsserver.CacheStats()
	totalLookups := cacheHits + cacheMisses
	hitPct := 0
	if totalLookups > 0 {
		hitPct = (cacheHits * 100) / totalLookups
	}
	ctCount, ctMax, ctErr := netstat.ConntrackStats()
	if ctErr != nil {
		log.Printf("read conntrack stats: %v", ctErr)
	}
	ctPct := 0
	if ctMax > 0 {
		ctPct = (ctCount * 100) / ctMax
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	snap := s.cfg.Snapshot()

	data := struct {
		DNSMode                                      string
		CacheEntries, CacheHits, CacheMisses, HitPct int
		TotalLookups                                 int
		ConntrackCount, ConntrackMax, ConntrackPct   int
		ConntrackAvailable                           bool
		MemAlloc, MemSys                             string
	}{
		DNSMode:            snap.DNSMode,
		CacheEntries:       cacheEntries,
		CacheHits:          cacheHits,
		CacheMisses:        cacheMisses,
		HitPct:             hitPct,
		TotalLookups:       totalLookups,
		ConntrackCount:     ctCount,
		ConntrackMax:       ctMax,
		ConntrackPct:       ctPct,
		ConntrackAvailable: ctErr == nil,
		MemAlloc:           netstat.HumanBytes(mem.Alloc),
		MemSys:             netstat.HumanBytes(mem.Sys),
	}

	if err := s.tmpl.ExecuteTemplate(w, "performance_fragment.html", data); err != nil {
		log.Printf("render performance fragment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// --- settings mutation handlers ---

func (s *Server) handleAddReservation(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	res := config.Reservation{
		MAC:       strings.TrimSpace(r.FormValue("mac")),
		IP:        strings.TrimSpace(r.FormValue("ip")),
		Hostname:  strings.TrimSpace(r.FormValue("hostname")),
		SegmentID: strings.TrimSpace(r.FormValue("segment_id")),
	}
	if res.MAC == "" || res.IP == "" || res.SegmentID == "" {
		http.Error(w, "mac, ip, and segment are required", http.StatusBadRequest)
		return
	}
	if err := s.cfg.AddReservation(res); err != nil {
		log.Printf("add reservation: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "")
}

func (s *Server) handleRemoveReservation(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := strings.TrimSpace(r.FormValue("mac"))
	if err := s.cfg.RemoveReservation(mac); err != nil {
		log.Printf("remove reservation: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "")
}

// handleQuickReserve is the dashboard-side "pin as static reservation"
// action from a device's expanded details row. Unlike
// handleAddReservation (used by the settings page), it re-renders the
// device list fragment so it can be used inline without navigating
// away from the dashboard.
func (s *Server) handleQuickReserve(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	res := config.Reservation{
		MAC:       strings.TrimSpace(r.FormValue("mac")),
		IP:        strings.TrimSpace(r.FormValue("ip")),
		Hostname:  strings.TrimSpace(r.FormValue("hostname")),
		SegmentID: strings.TrimSpace(r.FormValue("segment_id")),
	}
	if res.MAC == "" || res.IP == "" {
		http.Error(w, "mac and ip are required", http.StatusBadRequest)
		return
	}
	if err := s.cfg.AddReservation(res); err != nil {
		log.Printf("quick reserve: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.handleDevicesFragment(w, r)
}

// handleQuickRemoveReservation is the dashboard-side "remove
// reservation" action from a device's expanded details row. Mirrors
// handleQuickReserve: unlike handleRemoveReservation (used by the
// settings page), it re-renders the device list fragment in place
// rather than the full settings page.
func (s *Server) handleQuickRemoveReservation(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := strings.TrimSpace(r.FormValue("mac"))
	if err := s.cfg.RemoveReservation(mac); err != nil {
		log.Printf("quick remove reservation: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.handleDevicesFragment(w, r)
}

// handleQuickRemoveLease clears a dynamic (non-reserved) device entry
// from the dashboard. If the device is still actually connected, it
// will simply reappear on its next DHCP renewal - this just clears
// stale/known entries from view, it isn't a block.
func (s *Server) handleQuickRemoveLease(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := strings.TrimSpace(r.FormValue("mac"))
	if err := s.cfg.RemoveLease(mac); err != nil {
		log.Printf("quick remove lease: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.handleDevicesFragment(w, r)
}

// handleRenameDevice sets a persistent display-name override for a
// device. This is deliberately separate from just editing the
// Lease/Reservation's Hostname field directly: for a dynamic (non
// -reserved) device, that field gets overwritten by whatever the
// device itself reports on its next DHCP renewal, which would quietly
// undo a plain rename within a day. The override lives in its own map
// and always takes priority, so it survives renewals indefinitely -
// exactly what you'd want for permanently relabeling a device that
// keeps showing up as "(unknown)".
func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mac := strings.TrimSpace(r.FormValue("mac"))
	hostname := strings.TrimSpace(r.FormValue("hostname"))
	if mac == "" {
		http.Error(w, "mac is required", http.StatusBadRequest)
		return
	}
	if err := s.cfg.SetHostnameOverride(mac, hostname); err != nil {
		log.Printf("rename device: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.handleDevicesFragment(w, r)
}

func (s *Server) handleAddDNSRecord(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rec := config.DNSRecord{
		Name: strings.TrimSpace(r.FormValue("name")),
		IP:   strings.TrimSpace(r.FormValue("ip")),
	}
	if rec.Name == "" || rec.IP == "" {
		http.Error(w, "name and ip are required", http.StatusBadRequest)
		return
	}
	if err := s.cfg.AddDNSRecord(rec); err != nil {
		log.Printf("add dns record: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "")
}

func (s *Server) handleRemoveDNSRecord(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := s.cfg.RemoveDNSRecord(name); err != nil {
		log.Printf("remove dns record: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "")
}

func (s *Server) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	leaseSeconds, err := strconv.Atoi(strings.TrimSpace(r.FormValue("lease_seconds")))
	if err != nil {
		http.Error(w, "lease_seconds must be a number", http.StatusBadRequest)
		return
	}
	upstream := strings.Split(r.FormValue("upstream_servers"), ",")
	for i := range upstream {
		upstream[i] = strings.TrimSpace(upstream[i])
	}

	err = s.cfg.UpdateGlobalNetwork(
		strings.TrimSpace(r.FormValue("wan_interface")),
		strings.TrimSpace(r.FormValue("dns_mode")),
		leaseSeconds,
		upstream,
	)
	if err != nil {
		log.Printf("update network: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "")
}

// handleAddLANSegment adds a new VLAN/LAN segment from the settings
// page. Note that adding or removing a segment here doesn't start or
// stop its DHCP listener goroutine on its own - that only happens at
// process startup (see main.go), so a person needs to restart cobweb
// for a newly-added segment to actually begin serving DHCP. The
// dashboard will reflect this: a segment with no DHCP status reported
// yet just shows as "not running" until the next restart.
func (s *Server) handleAddLANSegment(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	dhcpDisabled := r.FormValue("dhcp_disabled") != ""
	seg := config.LANSegment{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Interface:    strings.TrimSpace(r.FormValue("interface")),
		Address:      strings.TrimSpace(r.FormValue("address")),
		SubnetMask:   strings.TrimSpace(r.FormValue("subnet_mask")),
		PoolStart:    strings.TrimSpace(r.FormValue("pool_start")),
		PoolEnd:      strings.TrimSpace(r.FormValue("pool_end")),
		Domain:       strings.TrimSpace(r.FormValue("domain")),
		DHCPDisabled: dhcpDisabled,
	}
	if seg.Name == "" || seg.Interface == "" || seg.Address == "" || seg.SubnetMask == "" {
		http.Error(w, "name, interface, address, and subnet mask are required", http.StatusBadRequest)
		return
	}
	if !dhcpDisabled && (seg.PoolStart == "" || seg.PoolEnd == "") {
		http.Error(w, "pool start and end are required unless DHCP is disabled for this segment", http.StatusBadRequest)
		return
	}
	// A DHCP-disabled segment (e.g. a switch management VLAN with only
	// static IPs) has no meaningful pool - default it to the
	// gateway's own address so nothing downstream ever sees an empty
	// string, even though no DHCP listener will actually run for it.
	if seg.PoolStart == "" {
		seg.PoolStart = seg.Address
	}
	if seg.PoolEnd == "" {
		seg.PoolEnd = seg.Address
	}
	if seg.Domain == "" {
		seg.Domain = "lan"
	}
	if _, err := s.cfg.AddLANSegment(seg); err != nil {
		log.Printf("add lan segment: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "Segment added. Restart cobweb for its DHCP listener to start.")
}

func (s *Server) handleRemoveLANSegment(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if err := s.cfg.RemoveLANSegment(id); err != nil {
		log.Printf("remove lan segment: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "Segment removed. Restart cobweb to stop its DHCP listener.")
}

// handleUpdateLANSegment edits an existing segment in place, keyed by
// its immutable ID - deliberately separate from remove+re-add, since
// re-adding always generates a fresh ID and would silently orphan any
// reservation or lease still pointing at the old one. This is the
// right way to fix something like "this segment's interface changed
// from enp1s0 to enp1s0.10" without losing data tied to it.
func (s *Server) handleUpdateLANSegment(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	dhcpDisabled := r.FormValue("dhcp_disabled") != ""
	seg := config.LANSegment{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Interface:    strings.TrimSpace(r.FormValue("interface")),
		Address:      strings.TrimSpace(r.FormValue("address")),
		SubnetMask:   strings.TrimSpace(r.FormValue("subnet_mask")),
		PoolStart:    strings.TrimSpace(r.FormValue("pool_start")),
		PoolEnd:      strings.TrimSpace(r.FormValue("pool_end")),
		Domain:       strings.TrimSpace(r.FormValue("domain")),
		DHCPDisabled: dhcpDisabled,
	}
	if id == "" || seg.Name == "" || seg.Interface == "" || seg.Address == "" || seg.SubnetMask == "" {
		http.Error(w, "name, interface, address, and subnet mask are required", http.StatusBadRequest)
		return
	}
	if !dhcpDisabled && (seg.PoolStart == "" || seg.PoolEnd == "") {
		http.Error(w, "pool start and end are required unless DHCP is disabled for this segment", http.StatusBadRequest)
		return
	}
	if seg.PoolStart == "" {
		seg.PoolStart = seg.Address
	}
	if seg.PoolEnd == "" {
		seg.PoolEnd = seg.Address
	}
	if seg.Domain == "" {
		seg.Domain = "lan"
	}
	if err := s.cfg.UpdateLANSegment(id, seg); err != nil {
		log.Printf("update lan segment: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "Segment updated. Restart cobweb for interface/DHCP changes to take effect.")
}

func (s *Server) handleAccountUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if !s.creds.Verify(s.creds.Username(), current) {
		s.renderSettings(w, r, "Current password is incorrect.", "")
		return
	}
	if newPass == "" || newPass != confirm {
		s.renderSettings(w, r, "New passwords do not match.", "")
		return
	}
	if len(newPass) < 8 {
		s.renderSettings(w, r, "New password must be at least 8 characters.", "")
		return
	}
	if err := s.creds.SetPassword(s.creds.Username(), newPass); err != nil {
		log.Printf("update password: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, "", "Password updated.")
}

// --- small helpers ---

func formatTimeLeft(expiresAt, now time.Time) string {
	if expiresAt.Before(now) {
		return "expired"
	}
	d := expiresAt.Sub(now)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
	}
	return strconv.Itoa(m) + "m"
}

// rowID turns a MAC address into a string safe to use as an HTML
// element id (colons aren't valid there).
func rowID(mac string) string {
	return strings.ReplaceAll(mac, ":", "")
}

// ipSortKey converts a dotted-quad IPv4 string into a numeric value so
// devices sort in true numeric order (192.168.2.9 before
// 192.168.2.10), not lexicographic string order.
func ipSortKey(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}
