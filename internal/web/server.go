package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cobweb/internal/config"
	"cobweb/internal/netstat"
)

// Server holds shared dependencies for HTTP handlers.
type Server struct {
	cfg  *config.Config
	tmpl *template.Template
}

//go:embed templates/*.html
var templateFS embed.FS

// New constructs a Server with templates parsed and ready to serve.
func New(cfg *config.Config) (*Server, error) {
	funcs := template.FuncMap{
		"join": strings.Join,
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, tmpl: tmpl}, nil
}

// Routes returns the configured HTTP mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/settings", s.handleSettingsPage)
	mux.HandleFunc("/fragments/devices", s.handleDevicesFragment)
	mux.HandleFunc("/fragments/interfaces", s.handleInterfacesFragment)
	mux.HandleFunc("/api/reservations/add", s.handleAddReservation)
	mux.HandleFunc("/api/reservations/remove", s.handleRemoveReservation)
	mux.HandleFunc("/api/dns/add", s.handleAddDNSRecord)
	mux.HandleFunc("/api/dns/remove", s.handleRemoveDNSRecord)
	mux.HandleFunc("/api/network/update", s.handleUpdateNetwork)
	return mux
}

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

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()
	if err := s.tmpl.ExecuteTemplate(w, "settings.html", snap); err != nil {
		log.Printf("render settings: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleDevicesFragment returns the device table body, built from
// current DHCP leases and static reservations - both live in cobweb's
// own config now, no external lease file to parse.
func (s *Server) handleDevicesFragment(w http.ResponseWriter, r *http.Request) {
	snap := s.cfg.Snapshot()
	now := time.Now()

	type row struct {
		Hostname string
		IP       string
		MAC      string
		Status   string // "reserved", "active", "expired"
		TimeLeft string
	}

	var rows []row
	seen := map[string]bool{}

	for _, res := range snap.Reservations {
		rows = append(rows, row{
			Hostname: displayHostname(res.Hostname),
			IP:       res.IP,
			MAC:      res.MAC,
			Status:   "reserved",
			TimeLeft: "static",
		})
		seen[res.MAC] = true
	}

	for _, l := range snap.Leases {
		if seen[l.MAC] {
			continue // already shown as a reservation above
		}
		expires := time.Unix(l.ExpiresAt, 0)
		status := "active"
		left := formatTimeLeft(expires, now)
		if expires.Before(now) {
			status = "expired"
		}
		rows = append(rows, row{
			Hostname: displayHostname(l.Hostname),
			IP:       l.IP,
			MAC:      l.MAC,
			Status:   status,
			TimeLeft: left,
		})
	}

	data := struct{ Rows []row }{Rows: rows}
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

	data := struct {
		WAN, LAN                   netstat.Interface
		WANRx, WANTx, LANRx, LANTx string
	}{
		WAN:   wan,
		LAN:   lan,
		WANRx: netstat.HumanBytes(wan.RxBytes),
		WANTx: netstat.HumanBytes(wan.TxBytes),
		LANRx: netstat.HumanBytes(lan.RxBytes),
		LANTx: netstat.HumanBytes(lan.TxBytes),
	}

	if err := s.tmpl.ExecuteTemplate(w, "interfaces_fragment.html", data); err != nil {
		log.Printf("render interfaces fragment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// --- settings mutation handlers ---
// Each of these is a plain HTML form POST (htmx-friendly: hx-post plus
// hx-target to swap the settings page back in), so no JS/JSON plumbing
// is required on the client side.

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
	s.handleSettingsPage(w, r)
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
	s.handleSettingsPage(w, r)
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
	s.handleSettingsPage(w, r)
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
	s.handleSettingsPage(w, r)
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
		leaseSeconds,
		upstream,
	)
	if err != nil {
		log.Printf("update network: %v", err)
		http.Error(w, "failed to save", http.StatusInternalServerError)
		return
	}
	s.handleSettingsPage(w, r)
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
