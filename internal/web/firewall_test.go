package web

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"cobweb/internal/auth"
	"cobweb/internal/config"
	"cobweb/internal/firewall"
)

// newTestServer builds a real Server (templates and all) over a temp
// config, with the kernel-touching apply step replaced by a recorder so
// no test ever runs nft.
func newTestServer(t *testing.T) (srv *Server, token string, applied *[]config.Snapshot) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(filepath.Join(dir, "config.json"))
	creds, err := auth.Load(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatalf("auth.Load: %v", err)
	}
	srv, err = New(cfg, creds)
	if err != nil {
		t.Fatalf("web.New (templates failed to parse?): %v", err)
	}
	srv.detectEnv = func() firewall.Environment { return firewall.Environment{} }
	var calls []config.Snapshot
	srv.applyFirewall = func(s config.Snapshot) error {
		calls = append(calls, s)
		return nil
	}
	token, err = srv.sessions.Create()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return srv, token, &calls
}

func do(srv *Server, token, method, path string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

func smbRule() url.Values {
	return url.Values{
		"name": {"SMB share"}, "kind": {"forward"}, "protocol": {"tcp"},
		"port": {"445"}, "to_ip": {"192.168.2.10"}, "source": {"192.168.1.0/24"},
	}
}

func TestSettingsPageRendersFirewallPanel(t *testing.T) {
	srv, token, _ := newTestServer(t)
	rr := do(srv, token, http.MethodGet, "/settings", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /settings = %d, want 200; body:\n%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"Firewall &amp; port forwarding", "Port rules", "Enable &amp; apply", "No rules yet.", "Show generated nftables ruleset"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
}

// Every state-changing /api route must refuse GET, even with a valid
// session, because the handlers read their input with FormValue (which
// includes the query string).
func TestMutatingRoutesRejectGET(t *testing.T) {
	srv, token, applied := newTestServer(t)
	paths := []string{
		"/api/reservations/add", "/api/reservations/remove", "/api/reservations/quickadd",
		"/api/reservations/quickremove", "/api/leases/quickremove", "/api/discovered/quickremove",
		"/api/devices/rename", "/api/dns/add", "/api/dns/remove", "/api/network/update",
		"/api/sqm/update", "/api/firewall/toggle", "/api/firewall/rules/add",
		"/api/firewall/rules/remove", "/api/firewall/rules/toggle", "/api/firewall/docker", "/api/firewall/trusted", "/api/segments/add",
		"/api/segments/update", "/api/segments/remove", "/api/config/import", "/api/account/update",
	}
	for _, p := range paths {
		rr := do(srv, token, http.MethodGet, p+"?enabled=1&mac=aa:bb:cc:dd:ee:ff&id=x", nil)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, rr.Code)
		}
	}
	if len(*applied) != 0 {
		t.Error("a rejected GET must never reach the firewall apply step")
	}
	if srv.cfg.Snapshot().FirewallEnabled {
		t.Error("GET /api/firewall/toggle?enabled=1 must not enable the firewall")
	}

	// Export is the one read-only /api route and stays a GET download.
	if rr := do(srv, token, http.MethodGet, "/api/config/export", nil); rr.Code != http.StatusOK {
		t.Errorf("GET /api/config/export = %d, want 200", rr.Code)
	}
}

func TestMutatingRoutesRequireLoginBeforeAnythingElse(t *testing.T) {
	srv, _, applied := newTestServer(t)
	rr := do(srv, "", http.MethodPost, "/api/firewall/toggle", url.Values{"enabled": {"1"}})
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated POST = %d -> %q, want 303 -> /login", rr.Code, rr.Header().Get("Location"))
	}
	if len(*applied) != 0 || srv.cfg.Snapshot().FirewallEnabled {
		t.Error("an unauthenticated request changed firewall state")
	}
}

func TestAddRuleWhileDisabledSavesButDoesNotTouchTheKernel(t *testing.T) {
	srv, token, applied := newTestServer(t)
	rr := do(srv, token, http.MethodPost, "/api/firewall/rules/add", smbRule())
	if rr.Code != http.StatusOK {
		t.Fatalf("add = %d; body:\n%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "takes effect once the firewall is enabled") {
		t.Error("expected the 'saved, not yet live' message")
	}
	rules := srv.cfg.Snapshot().PortRules
	if len(rules) != 1 || rules[0].Port != "445" || rules[0].ID == "" {
		t.Fatalf("rule not stored correctly: %+v", rules)
	}
	if len(*applied) != 0 {
		t.Errorf("firewall is off, so nothing should have been applied; got %d apply calls", len(*applied))
	}
}

func TestEnableThenAddAppliesEachChange(t *testing.T) {
	srv, token, applied := newTestServer(t)

	rr := do(srv, token, http.MethodPost, "/api/firewall/toggle", url.Values{"enabled": {"1"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Firewall enabled") {
		t.Fatalf("enable failed: %d\n%s", rr.Code, rr.Body.String())
	}
	if !srv.cfg.Snapshot().FirewallEnabled || len(*applied) != 1 {
		t.Fatalf("expected enabled + 1 apply, got enabled=%v applies=%d", srv.cfg.Snapshot().FirewallEnabled, len(*applied))
	}

	rr = do(srv, token, http.MethodPost, "/api/firewall/rules/add", smbRule())
	if !strings.Contains(rr.Body.String(), "Rule added and applied") {
		t.Fatalf("expected an 'added and applied' message:\n%s", rr.Body.String())
	}
	if len(*applied) != 2 {
		t.Fatalf("adding a rule while enabled should apply once more; applies=%d", len(*applied))
	}
	last := (*applied)[1]
	if !last.FirewallEnabled || len(last.PortRules) != 1 {
		t.Errorf("apply received a stale snapshot: %+v", last)
	}

	// The preview on the page is the real rendered ruleset.
	body := do(srv, token, http.MethodGet, "/settings", nil).Body.String()
	for _, want := range []string{"dnat to 192.168.2.10", "tcp dport 445", "192.168.1.0/24"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview missing %q", want)
		}
	}
}

func TestInvalidRuleIsRejectedWithoutSavingOrApplying(t *testing.T) {
	srv, token, applied := newTestServer(t)
	bad := smbRule()
	bad.Set("to_ip", "10.99.99.99") // not inside any configured segment
	rr := do(srv, token, http.MethodPost, "/api/firewall/rules/add", bad)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid rule = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "inside any configured LAN segment") {
		t.Error("the error should say why the rule was rejected")
	}
	if len(srv.cfg.Snapshot().PortRules) != 0 || len(*applied) != 0 {
		t.Error("an invalid rule must be neither saved nor applied")
	}
}

func TestInputRuleDropsStrayTargetFields(t *testing.T) {
	srv, token, _ := newTestServer(t)
	form := url.Values{
		"name": {"files"}, "kind": {"input"}, "protocol": {"tcp"}, "port": {"8081"},
		"to_ip": {"not even an ip"}, "to_port": {"zzz"}, "source": {"192.168.1.5"},
	}
	rr := do(srv, token, http.MethodPost, "/api/firewall/rules/add", form)
	if rr.Code != http.StatusOK {
		t.Fatalf("input rule = %d; body:\n%s", rr.Code, rr.Body.String())
	}
	r := srv.cfg.Snapshot().PortRules[0]
	if r.ToIP != "" || r.ToPort != "" {
		t.Errorf("an input rule shouldn't keep target fields: %+v", r)
	}
}

func TestFailedApplyRollsTheRuleBack(t *testing.T) {
	srv, token, _ := newTestServer(t)
	if err := srv.cfg.SetFirewallEnabled(true); err != nil {
		t.Fatal(err)
	}
	srv.applyFirewall = func(config.Snapshot) error { return errors.New("nft exploded") }

	rr := do(srv, token, http.MethodPost, "/api/firewall/rules/add", smbRule())
	if !strings.Contains(rr.Body.String(), "nft exploded") || !strings.Contains(rr.Body.String(), "nothing was changed") {
		t.Errorf("expected the real error and a reassurance:\n%s", rr.Body.String())
	}
	if n := len(srv.cfg.Snapshot().PortRules); n != 0 {
		t.Errorf("a rule that couldn't be applied must be rolled back; %d rule(s) remain", n)
	}
}

func TestFailedEnableRevertsToOff(t *testing.T) {
	srv, token, _ := newTestServer(t)
	srv.applyFirewall = func(config.Snapshot) error { return errors.New("nft: command not found") }

	rr := do(srv, token, http.MethodPost, "/api/firewall/toggle", url.Values{"enabled": {"1"}})
	if !strings.Contains(rr.Body.String(), "Not enabled") || !strings.Contains(rr.Body.String(), "command not found") {
		t.Errorf("expected a 'Not enabled' message with the real error:\n%s", rr.Body.String())
	}
	if srv.cfg.Snapshot().FirewallEnabled {
		t.Error("the saved setting must not claim the firewall is on when applying it failed")
	}
}

func TestRemoveAndToggleRule(t *testing.T) {
	srv, token, applied := newTestServer(t)
	do(srv, token, http.MethodPost, "/api/firewall/rules/add", smbRule())
	do(srv, token, http.MethodPost, "/api/firewall/toggle", url.Values{"enabled": {"1"}})
	id := srv.cfg.Snapshot().PortRules[0].ID
	*applied = nil

	rr := do(srv, token, http.MethodPost, "/api/firewall/rules/toggle", url.Values{"id": {id}, "disabled": {"1"}})
	if !strings.Contains(rr.Body.String(), "Rule turned off") || !srv.cfg.Snapshot().PortRules[0].Disabled {
		t.Fatalf("toggle off failed:\n%s", rr.Body.String())
	}
	if len(*applied) != 1 {
		t.Errorf("toggling a rule while enabled should apply; applies=%d", len(*applied))
	}

	rr = do(srv, token, http.MethodPost, "/api/firewall/rules/toggle", url.Values{"id": {"rule-nope"}, "disabled": {"1"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("toggling a missing rule = %d, want 400", rr.Code)
	}

	rr = do(srv, token, http.MethodPost, "/api/firewall/rules/remove", url.Values{"id": {id}})
	if !strings.Contains(rr.Body.String(), "Rule removed") || len(srv.cfg.Snapshot().PortRules) != 0 {
		t.Fatalf("remove failed:\n%s", rr.Body.String())
	}
}

func dockerForm(enabled, ifaces, source string) url.Values {
	return url.Values{"docker_enabled": {enabled}, "docker_interfaces": {ifaces}, "docker_wan_source": {source}}
}

func TestDockerSettingsSaveAndApplyWhenFirewallIsOn(t *testing.T) {
	srv, token, applied := newTestServer(t)
	_ = srv.cfg.SetFirewallEnabled(true)

	rr := do(srv, token, http.MethodPost, "/api/firewall/docker", dockerForm("1", "docker0, br-*  custom0", "192.168.1.20"))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Docker containers are now allowed through") {
		t.Fatalf("got %d; body:\n%s", rr.Code, rr.Body.String())
	}
	snap := srv.cfg.Snapshot()
	if !snap.DockerEnabled || snap.DockerWANSource != "192.168.1.20" {
		t.Fatalf("not saved: %+v", snap)
	}
	if got := strings.Join(snap.DockerInterfaces, "|"); got != "docker0|br-*|custom0" {
		t.Fatalf("interfaces = %q, want the comma/space separated list split", got)
	}
	if len(*applied) != 1 || !(*applied)[0].DockerEnabled {
		t.Fatalf("expected one apply with docker on, got %d", len(*applied))
	}
}

func TestDockerSettingsWhileFirewallOffAreSavedButNotApplied(t *testing.T) {
	srv, token, applied := newTestServer(t)
	rr := do(srv, token, http.MethodPost, "/api/firewall/docker", dockerForm("1", "", ""))
	if !strings.Contains(rr.Body.String(), "take effect once the firewall is enabled") {
		t.Fatalf("unexpected message:\n%s", rr.Body.String())
	}
	if !srv.cfg.Snapshot().DockerEnabled || len(*applied) != 0 {
		t.Fatal("expected saved without touching the kernel")
	}
}

func TestDockerSettingsRejectInterfacesThatCouldMatchTheWANOrALAN(t *testing.T) {
	for _, bad := range []string{"wl*", "enp*", "*", `docker0" accept`, "lo", "a-very-long-interface-name"} {
		srv, token, applied := newTestServer(t)
		_ = srv.cfg.SetFirewallEnabled(true)
		rr := do(srv, token, http.MethodPost, "/api/firewall/docker", dockerForm("1", bad, ""))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%q: got %d, want 400", bad, rr.Code)
		}
		if srv.cfg.Snapshot().DockerEnabled || len(*applied) != 0 {
			t.Errorf("%q: rejected settings were saved or applied", bad)
		}
	}
	srv, token, _ := newTestServer(t)
	if rr := do(srv, token, http.MethodPost, "/api/firewall/docker", dockerForm("1", "", "not-an-ip")); rr.Code != http.StatusBadRequest {
		t.Errorf("bad source: got %d, want 400", rr.Code)
	}
}

func TestDockerSettingsRollBackWhenApplyFails(t *testing.T) {
	srv, token, _ := newTestServer(t)
	_ = srv.cfg.SetFirewallEnabled(true)
	srv.applyFirewall = func(config.Snapshot) error { return errors.New("nft said no") }
	rr := do(srv, token, http.MethodPost, "/api/firewall/docker", dockerForm("1", "", ""))
	if !strings.Contains(rr.Body.String(), "nothing was changed") || srv.cfg.Snapshot().DockerEnabled {
		t.Fatalf("expected rollback; docker=%v body:\n%s", srv.cfg.Snapshot().DockerEnabled, rr.Body.String())
	}
}

func TestSettingsPageExplainsDockersDropPolicyAndTheFix(t *testing.T) {
	srv, token, _ := newTestServer(t)
	srv.detectEnv = func() firewall.Environment {
		return firewall.Environment{
			DockerDetected:     true,
			ForwardDrops:       []string{"ip filter FORWARD"},
			DockerForwardDrops: []string{"ip filter FORWARD"},
		}
	}
	body := do(srv, token, http.MethodGet, "/settings", nil).Body.String()
	for _, want := range []string{"Docker is cutting off forwarded traffic", "ip filter FORWARD", "ip-forward-no-drop", "/etc/docker/daemon.json", "systemctl restart docker"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}

	// No Docker, no scary banner. (An unrelated forward-drop table is covered by the
	// generic "other tables" notice, not this one.)
	srv.detectEnv = func() firewall.Environment {
		return firewall.Environment{ForwardDrops: []string{"inet filter forward"}}
	}
	if body := do(srv, token, http.MethodGet, "/settings", nil).Body.String(); strings.Contains(body, "Docker is cutting off") {
		t.Error("the Docker warning appeared for a non-Docker table")
	}
}

func TestSettingsPageNudgesWhenDockerIsInstalledButNotAllowed(t *testing.T) {
	srv, token, _ := newTestServer(t)
	_ = srv.cfg.SetFirewallEnabled(true)
	srv.detectEnv = func() firewall.Environment { return firewall.Environment{DockerDetected: true} }
	if body := do(srv, token, http.MethodGet, "/settings", nil).Body.String(); !strings.Contains(body, "containers currently have no network") {
		t.Error("expected the Docker-installed-but-off notice")
	}
	_ = srv.cfg.SetDocker(true, nil, "")
	if body := do(srv, token, http.MethodGet, "/settings", nil).Body.String(); strings.Contains(body, "containers currently have no network") {
		t.Error("the notice should disappear once Docker is allowed")
	}
}

func TestTrustedSettingsSaveApplyAndRender(t *testing.T) {
	srv, token, applied := newTestServer(t)
	_ = srv.cfg.SetFirewallEnabled(true)
	rr := do(srv, token, http.MethodPost, "/api/firewall/trusted", url.Values{"trusted_interfaces": {"wg0, wg1"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "VPN interfaces are now trusted") {
		t.Fatalf("got %d:\n%s", rr.Code, rr.Body.String())
	}
	if got := strings.Join(srv.cfg.Snapshot().TrustedInterfaces, "|"); got != "wg0|wg1" {
		t.Fatalf("saved %q", got)
	}
	if len(*applied) != 1 {
		t.Fatalf("applies = %d, want 1", len(*applied))
	}
	if !strings.Contains(rr.Body.String(), `value="wg0, wg1"`) {
		t.Fatal("form doesn't show the saved list")
	}
	rr = do(srv, token, http.MethodPost, "/api/firewall/trusted", url.Values{"trusted_interfaces": {""}})
	if !strings.Contains(rr.Body.String(), "No interfaces are trusted") || len(srv.cfg.Snapshot().TrustedInterfaces) != 0 {
		t.Fatalf("clearing failed:\n%s", rr.Body.String())
	}
}

func TestTrustedSettingsWhileFirewallOffAreNotApplied(t *testing.T) {
	srv, token, applied := newTestServer(t)
	rr := do(srv, token, http.MethodPost, "/api/firewall/trusted", url.Values{"trusted_interfaces": {"wg0"}})
	if !strings.Contains(rr.Body.String(), "take effect once the firewall is enabled") || len(*applied) != 0 {
		t.Fatalf("unexpected:\n%s", rr.Body.String())
	}
}

func TestTrustedSettingsRejectDangerousInterfaces(t *testing.T) {
	for _, bad := range []string{"wl*", "enp*", "*", "lo", `wg0" accept`, "docker0"} {
		srv, token, applied := newTestServer(t)
		_ = srv.cfg.SetFirewallEnabled(true)
		_ = srv.cfg.SetDocker(true, nil, "")
		before := len(*applied)
		rr := do(srv, token, http.MethodPost, "/api/firewall/trusted", url.Values{"trusted_interfaces": {bad}})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%q: got %d, want 400", bad, rr.Code)
		}
		if len(srv.cfg.Snapshot().TrustedInterfaces) != 0 || len(*applied) != before {
			t.Errorf("%q: rejected input was saved or applied", bad)
		}
	}
}

func TestTrustedSettingsRollBackWhenApplyFails(t *testing.T) {
	srv, token, _ := newTestServer(t)
	_ = srv.cfg.SetFirewallEnabled(true)
	srv.applyFirewall = func(config.Snapshot) error { return errors.New("nft said no") }
	rr := do(srv, token, http.MethodPost, "/api/firewall/trusted", url.Values{"trusted_interfaces": {"wg0"}})
	if !strings.Contains(rr.Body.String(), "nothing was changed") || len(srv.cfg.Snapshot().TrustedInterfaces) != 0 {
		t.Fatalf("expected rollback:\n%s", rr.Body.String())
	}
}

func TestDockerSettingsCannotOverlapTrusted(t *testing.T) {
	srv, token, _ := newTestServer(t)
	_ = srv.cfg.SetTrustedInterfaces([]string{"br-vpn"})
	rr := do(srv, token, http.MethodPost, "/api/firewall/docker", dockerForm("1", "", ""))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("docker defaults overlapping a trusted interface: got %d, want 400", rr.Code)
	}
}
