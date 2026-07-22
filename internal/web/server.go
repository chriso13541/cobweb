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
	mux.HandleFunc("/fragments/devices", s.requireAuth(s.handleDevicesFragment))
	mux.HandleFunc("/fragments/interfaces", s.requireAuth(s.handleInterfacesFragment))
	mux.HandleFunc("/fragments/performance", s.requireAuth(s.handlePerformanceFragment))
	mux.HandleFunc("/api/reservations/add", s.requireAuth(s.handleAddReservation))
	mux.HandleFunc("/api/reservations/remove", s.requireAuth(s.handleRemoveReservation))
	mux.HandleFunc("/api/reservations/quickadd", s.requireAuth(s.handleQuickReserve))
	mux.HandleFunc("/api/reservations/quickremove", s.requireAuth(s.handleQuickRemoveReservation))
	mux.HandleFunc("/api/leases/quickremove", s.requireAuth(s.handleQuickRemoveLease))
	mux.HandleFunc("/api/dns/add", s.requireAuth(s.handleAddDNSRecord))
	mux.HandleFunc("/api/dns/remove", s.requireAuth(s.handleRemoveDNSRecord))
	mux.HandleFunc("/api/network/update", s.requireAuth(s.handleUpdateNetwork))
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
	if err := s.tmpl.ExecuteTemplate(w, "dashboard.html", nil); err != nil {
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
	Status          string // "reserved", "active", "expired"
	TimeLeft        string
	ExpiresAbsolute string
	Reserved        bool
}

// handleDevicesFragment returns the device table body, built from
// current DHCP leases and static reservations - both live in cobweb's
// own config now, no external lease file to parse. Supports optional
// ?q=, ?sort=, ?dir= query params for search and sorting, used by the
// dashboard's search box and clickable column headers.
func (s *Server) handleDevicesFragment(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()
	now := time.Now()

	var rows []deviceRow
	seen := map[string]bool{}

	for _, res := range snap.Reservations {
		rows = append(rows, deviceRow{
			RowID:           rowID(res.MAC),
			Hostname:        displayHostname(res.Hostname),
			IP:              res.IP,
			MAC:             res.MAC,
			Status:          "reserved",
			TimeLeft:        "static",
			ExpiresAbsolute: "Permanent (static reservation)",
			Reserved:        true,
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
		rows = append(rows, deviceRow{
			RowID:           rowID(l.MAC),
			Hostname:        displayHostname(l.Hostname),
			IP:              l.IP,
			MAC:             l.MAC,
			Status:          st,
			TimeLeft:        formatTimeLeft(expires, now),
			ExpiresAbsolute: expires.Format("Jan 2, 3:04 PM"),
			Reserved:        false,
		})
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

func (s *Server) handleInterfacesFragment(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()

	wan, err := netstat.Stat(snap.WANInterface)
	if err != nil {
		log.Printf("stat wan interface %s: %v", snap.WANInterface, err)
	}
	lan, err := netstat.Stat(snap.LANInterface)
	if err != nil {
		log.Printf("stat lan interface %s: %v", snap.LANInterface, err)
	}

	dhcpState, dnsState := status.Snapshot()

	data := struct {
		WAN, LAN                   netstat.Interface
		WANRx, WANTx, LANRx, LANTx string
		DHCPUp, DNSUp              bool
		DHCPErr, DNSErr            string
	}{
		WAN:     wan,
		LAN:     lan,
		WANRx:   netstat.HumanBytes(wan.RxBytes),
		WANTx:   netstat.HumanBytes(wan.TxBytes),
		LANRx:   netstat.HumanBytes(lan.RxBytes),
		LANTx:   netstat.HumanBytes(lan.TxBytes),
		DHCPUp:  dhcpState.Up,
		DNSUp:   dnsState.Up,
		DHCPErr: dhcpState.LastErr,
		DNSErr:  dnsState.LastErr,
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
		MAC:      strings.TrimSpace(r.FormValue("mac")),
		IP:       strings.TrimSpace(r.FormValue("ip")),
		Hostname: strings.TrimSpace(r.FormValue("hostname")),
	}
	if res.MAC == "" || res.IP == "" {
		http.Error(w, "mac and ip are required", http.StatusBadRequest)
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
		MAC:      strings.TrimSpace(r.FormValue("mac")),
		IP:       strings.TrimSpace(r.FormValue("ip")),
		Hostname: strings.TrimSpace(r.FormValue("hostname")),
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

	err = s.cfg.UpdateNetwork(
		strings.TrimSpace(r.FormValue("wan_interface")),
		strings.TrimSpace(r.FormValue("lan_interface")),
		strings.TrimSpace(r.FormValue("lan_address")),
		strings.TrimSpace(r.FormValue("subnet_mask")),
		strings.TrimSpace(r.FormValue("pool_start")),
		strings.TrimSpace(r.FormValue("pool_end")),
		strings.TrimSpace(r.FormValue("domain")),
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

func displayHostname(h string) string {
	if h == "" {
		return "(unknown)"
	}
	return h
}

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
