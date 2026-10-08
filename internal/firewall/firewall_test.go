package firewall

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"cobweb/internal/config"
)

func testSnap(rules ...config.PortRule) config.Snapshot {
	return config.Snapshot{
		WANInterface: "wlp2s0",
		LANSegments: []config.LANSegment{
			{ID: "seg-a", Name: "Room", Interface: "enp1s0", Address: "192.168.2.1", SubnetMask: "255.255.255.0"},
			{ID: "seg-b", Name: "IoT", Interface: "enp1s0.20", Address: "192.168.20.1", SubnetMask: "255.255.255.0"},
		},
		FirewallEnabled: true,
		PortRules:       rules,
	}
}

func mustRender(t *testing.T, snap config.Snapshot) string {
	t.Helper()
	out, err := Render(snap)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out
}

func requireContains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("ruleset missing %q\n--- ruleset ---\n%s", n, haystack)
		}
	}
}

func TestRenderBaseline(t *testing.T) {
	out := mustRender(t, testSnap())
	requireContains(t, out,
		"table inet cobweb\ndelete table inet cobweb\n",
		"table ip cobweb_nat\ndelete table ip cobweb_nat\n",
		"type filter hook input priority 0; policy drop;",
		"type filter hook forward priority 0; policy drop;",
		`iifname { "enp1s0", "enp1s0.20" } accept`,
		`iifname { "enp1s0", "enp1s0.20" } oifname { "enp1s0", "enp1s0.20" } accept`,
		`iifname { "enp1s0", "enp1s0.20" } oifname "wlp2s0" accept`,
		`oifname "wlp2s0" masquerade`,
		"meta l4proto { 1, 58 } accept",
	)
}

func TestForwardRuleSMBFromHouseNetwork(t *testing.T) {
	out := mustRender(t, testSnap(config.PortRule{
		ID: "r1", Name: "SMB share", Kind: config.RuleForward, Protocol: "tcp",
		Port: "445", ToIP: "192.168.2.10", Source: "192.168.1.0/24",
	}))
	requireContains(t, out,
		`iifname "wlp2s0" fib daddr type local ip saddr 192.168.1.0/24 tcp dport 445 dnat to 192.168.2.10 comment "SMB share"`,
		`iifname "wlp2s0" ip saddr 192.168.1.0/24 ip daddr 192.168.2.10 tcp dport 445 accept comment "SMB share"`,
	)
}

func TestForwardRuleRemapsPortAndUsesPostNATPortInForwardChain(t *testing.T) {
	out := mustRender(t, testSnap(config.PortRule{
		Name: "web", Kind: config.RuleForward, Protocol: "tcp",
		Port: "8080", ToIP: "192.168.2.10", ToPort: "80",
	}))
	// dnat rewrites 8080 -> 80 in prerouting, so the forward chain (which
	// runs afterwards) must match on 80, not the original 8080.
	requireContains(t, out,
		"tcp dport 8080 dnat to 192.168.2.10:80",
		"ip daddr 192.168.2.10 tcp dport 80 accept",
	)
}

func TestForwardRuleRangeKeepsPorts(t *testing.T) {
	out := mustRender(t, testSnap(config.PortRule{
		Name: "range", Kind: config.RuleForward, Protocol: "udp",
		Port: "8000-8010", ToIP: "192.168.20.5",
	}))
	requireContains(t, out,
		"udp dport 8000-8010 dnat to 192.168.20.5",
		"ip daddr 192.168.20.5 udp dport 8000-8010 accept",
	)
}

func TestBothProtocolsEmitsTCPAndUDP(t *testing.T) {
	out := mustRender(t, testSnap(config.PortRule{
		Name: "dns-ish", Kind: config.RuleInput, Protocol: "both", Port: "5353", Source: "192.168.1.5",
	}))
	requireContains(t, out,
		`iifname "wlp2s0" ip saddr 192.168.1.5 tcp dport 5353 accept`,
		`iifname "wlp2s0" ip saddr 192.168.1.5 udp dport 5353 accept`,
	)
}

func TestInputRuleAndNoSourceMeansAnyWANHost(t *testing.T) {
	out := mustRender(t, testSnap(config.PortRule{
		Name: "files", Kind: config.RuleInput, Protocol: "tcp", Port: "8080",
	}))
	requireContains(t, out, `iifname "wlp2s0" tcp dport 8080 accept comment "files"`)
	if strings.Contains(out, "saddr") {
		t.Errorf("a rule with no Source shouldn't emit any saddr match:\n%s", out)
	}
}

func TestDisabledRulesAreNotRendered(t *testing.T) {
	out := mustRender(t, testSnap(config.PortRule{
		Name: "off", Kind: config.RuleInput, Protocol: "tcp", Port: "9999", Disabled: true,
	}))
	if strings.Contains(out, "9999") {
		t.Errorf("disabled rule leaked into ruleset:\n%s", out)
	}
}

func TestInvalidRulesAreRejected(t *testing.T) {
	segs := testSnap().LANSegments
	cases := []struct {
		name string
		rule config.PortRule
		want string
	}{
		{"bad kind", config.PortRule{Kind: "nope", Protocol: "tcp", Port: "1"}, "type must be"},
		{"bad protocol", config.PortRule{Kind: "input", Protocol: "icmp", Port: "1"}, "protocol"},
		{"port zero", config.PortRule{Kind: "input", Protocol: "tcp", Port: "0"}, "valid port"},
		{"port too big", config.PortRule{Kind: "input", Protocol: "tcp", Port: "70000"}, "valid port"},
		{"port junk", config.PortRule{Kind: "input", Protocol: "tcp", Port: "80; flush ruleset"}, "valid port"},
		{"backwards range", config.PortRule{Kind: "input", Protocol: "tcp", Port: "10-5"}, "backwards"},
		{"bad source", config.PortRule{Kind: "input", Protocol: "tcp", Port: "1", Source: "not-an-ip"}, "source"},
		{"ipv6 source", config.PortRule{Kind: "input", Protocol: "tcp", Port: "1", Source: "fe80::1"}, "source"},
		{"host bits set", config.PortRule{Kind: "input", Protocol: "tcp", Port: "1", Source: "192.168.1.5/24"}, "host bits"},
		{"forward no target", config.PortRule{Kind: "forward", Protocol: "tcp", Port: "445"}, "target"},
		{"target outside segments", config.PortRule{Kind: "forward", Protocol: "tcp", Port: "445", ToIP: "10.9.9.9"}, "inside any configured LAN segment"},
		{"target is the router", config.PortRule{Kind: "forward", Protocol: "tcp", Port: "445", ToIP: "192.168.2.1"}, "router's own address"},
		{"range with remap", config.PortRule{Kind: "forward", Protocol: "tcp", Port: "1-5", ToIP: "192.168.2.10", ToPort: "80"}, "range"},
		{"bad to-port", config.PortRule{Kind: "forward", Protocol: "tcp", Port: "80", ToIP: "192.168.2.10", ToPort: "x"}, "target port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.rule, segs)
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

// TestHostileConfigCannotInjectNftSyntax is the important one: config
// can be hand-edited or imported, so nothing in it may reach the
// ruleset except through the parsed, re-stringified path.
func TestHostileConfigCannotInjectNftSyntax(t *testing.T) {
	// A hostile rule name is only ever used as a character-filtered comment.
	out := mustRender(t, testSnap(config.PortRule{
		Name: "x\"\n}\nflush ruleset\n#", Kind: config.RuleInput, Protocol: "tcp", Port: "80",
	}))
	// The words may survive inside the comment (that's harmless text), but
	// they must never start a statement, and the comment must stay one
	// quoted run of safe characters at the end of its own single line.
	commentRe := regexp.MustCompile(`^"[A-Za-z0-9 ._-]*"$`)
	sawComment := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "flush") {
			t.Errorf("hostile rule name produced a statement: %q", line)
		}
		if _, after, ok := strings.Cut(line, " comment "); ok {
			sawComment = true
			if !commentRe.MatchString(after) {
				t.Errorf("comment isn't a single safely-quoted run: %q", after)
			}
		}
	}
	if !sawComment {
		t.Error("expected the rule's sanitized name to appear as a comment")
	}

	// Hostile interface names are rejected outright, not sanitized.
	snap := testSnap()
	snap.LANSegments[0].Interface = `enp1s0" accept; flush ruleset; "`
	if _, err := Render(snap); err == nil {
		t.Error("expected a hostile LAN interface name to be rejected")
	}
	snap = testSnap()
	snap.WANInterface = "wlp2s0\nflush ruleset"
	if _, err := Render(snap); err == nil {
		t.Error("expected a hostile WAN interface name to be rejected")
	}
}

func TestRenderRejectsBadTopology(t *testing.T) {
	snap := testSnap()
	snap.LANSegments = nil
	if _, err := Render(snap); err == nil {
		t.Error("expected an error with no LAN segments")
	}
	snap = testSnap()
	snap.LANSegments[0].Interface = snap.WANInterface
	if _, err := Render(snap); err == nil {
		t.Error("expected an error when a LAN segment uses the WAN interface")
	}
}

func TestRenderReportsWhichRuleIsBad(t *testing.T) {
	_, err := Render(testSnap(config.PortRule{ID: "r9", Name: "broken", Kind: config.RuleInput, Protocol: "tcp", Port: "nope"}))
	if err == nil || !strings.Contains(err.Error(), `"broken"`) {
		t.Fatalf("error should name the offending rule, got: %v", err)
	}
}

// --- Apply ---

type call struct {
	stdin string
	args  []string
}

func fakeRunner(t *testing.T, failOn func(c call) error) *[]call {
	t.Helper()
	var calls []call
	orig := runFn
	origFwd := enableForwardingFn
	runFn = func(stdin, name string, args ...string) error {
		c := call{stdin: stdin, args: append([]string{name}, args...)}
		calls = append(calls, c)
		if failOn != nil {
			return failOn(c)
		}
		return nil
	}
	enableForwardingFn = func() error { return nil }
	t.Cleanup(func() { runFn = orig; enableForwardingFn = origFwd })
	return &calls
}

func TestApplyChecksThenInstalls(t *testing.T) {
	calls := fakeRunner(t, nil)
	if err := Apply(testSnap()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("expected 2 nft calls (check, apply), got %d", len(*calls))
	}
	if got := strings.Join((*calls)[0].args, " "); got != "nft -c -f -" {
		t.Errorf("first call = %q, want the -c syntax check", got)
	}
	if got := strings.Join((*calls)[1].args, " "); got != "nft -f -" {
		t.Errorf("second call = %q, want the real apply", got)
	}
	if (*calls)[0].stdin != (*calls)[1].stdin || !strings.Contains((*calls)[1].stdin, "table inet cobweb") {
		t.Error("check and apply must be fed the same ruleset")
	}
}

func TestApplyDoesNotInstallIfSyntaxCheckFails(t *testing.T) {
	calls := fakeRunner(t, func(c call) error {
		if len(c.args) > 1 && c.args[1] == "-c" {
			return errors.New("syntax error")
		}
		return nil
	})
	err := Apply(testSnap())
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("expected a 'nothing was changed' error, got: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("a failed check must stop before the real apply; got %d calls", len(*calls))
	}
}

func TestApplyDisabledOnlyRemovesCobwebTables(t *testing.T) {
	calls := fakeRunner(t, nil)
	snap := testSnap()
	snap.FirewallEnabled = false
	if err := Apply(snap); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected a single teardown call, got %d", len(*calls))
	}
	in := (*calls)[0].stdin
	requireContains(t, in, "delete table inet cobweb", "delete table ip cobweb_nat")
	if strings.Contains(in, "filter") || strings.Contains(in, "flush") {
		t.Errorf("teardown must only touch cobweb's own tables:\n%s", in)
	}
}

func TestApplyDoesNotRunNftWhenRenderFails(t *testing.T) {
	calls := fakeRunner(t, nil)
	snap := testSnap()
	snap.WANInterface = ""
	if err := Apply(snap); err == nil {
		t.Fatal("expected a render error")
	}
	if len(*calls) != 0 {
		t.Fatalf("nft must not run when the ruleset can't even be rendered; got %d calls", len(*calls))
	}
}

// --- Warnings / ForeignTables ---

func TestWarnsAboutMissingSSHRule(t *testing.T) {
	w := Warnings(testSnap())
	if len(w) == 0 || !strings.Contains(w[0], "SSH") {
		t.Fatalf("expected an SSH lockout warning, got %v", w)
	}

	w = Warnings(testSnap(config.PortRule{Name: "ssh", Kind: config.RuleInput, Protocol: "tcp", Port: "22", Source: "192.168.1.5"}))
	for _, msg := range w {
		if strings.Contains(msg, "SSH") {
			t.Errorf("SSH is allowed, shouldn't warn: %q", msg)
		}
	}

	// A range that happens to include 22 counts too.
	w = Warnings(testSnap(config.PortRule{Name: "wide", Kind: config.RuleInput, Protocol: "both", Port: "1-1024", Source: "192.168.1.0/24"}))
	for _, msg := range w {
		if strings.Contains(msg, "SSH") {
			t.Errorf("range covers 22, shouldn't warn: %q", msg)
		}
	}
}

func TestWarnsAboutRulesWithNoSource(t *testing.T) {
	w := Warnings(testSnap(config.PortRule{Name: "open", Kind: config.RuleInput, Protocol: "tcp", Port: "8080"}))
	found := false
	for _, msg := range w {
		if strings.Contains(msg, `"open"`) && strings.Contains(msg, "any address") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an any-source warning for rule \"open\", got %v", w)
	}
}

func TestForeignTablesIgnoresCobwebsOwn(t *testing.T) {
	orig := outputFn
	t.Cleanup(func() { outputFn = orig })
	outputFn = func(name string, args ...string) (string, error) {
		return "table inet filter\ntable ip nat\ntable inet cobweb\ntable ip cobweb_nat\n", nil
	}
	got := ForeignTables()
	if len(got) != 2 || got[0] != "inet filter" || got[1] != "ip nat" {
		t.Fatalf("ForeignTables = %v, want [inet filter, ip nat]", got)
	}

	outputFn = func(name string, args ...string) (string, error) { return "", errors.New("nft: not found") }
	if got := ForeignTables(); got != nil {
		t.Fatalf("expected nil when nft is unavailable, got %v", got)
	}
}

// --- Docker ---

func dockerSnap(mut func(*config.Snapshot)) config.Snapshot {
	snap := testSnap()
	snap.DockerEnabled = true
	if mut != nil {
		mut(&snap)
	}
	return snap
}

func TestDockerOffRendersExactlyTheBaseline(t *testing.T) {
	off := testSnap()
	off.DockerInterfaces = []string{"docker0"} // configured but not enabled: must have no effect
	off.DockerWANSource = "192.168.1.20"
	if a, b := mustRender(t, off), mustRender(t, testSnap()); a != b {
		t.Fatalf("Docker settings changed the ruleset while disabled:\n%s\n--- vs ---\n%s", a, b)
	}
	if strings.Contains(mustRender(t, testSnap()), "docker") {
		t.Fatal("baseline ruleset mentions docker")
	}
}

func TestDockerRulesUseDefaultBridges(t *testing.T) {
	out := mustRender(t, dockerSnap(nil))
	lans := `{ "enp1s0", "enp1s0.20" }`
	for _, d := range []string{"docker0", "br-*"} {
		requireContains(t, out,
			`iifname "`+d+`" accept comment`,                         // containers -> the router itself
			`iifname "`+d+`" oifname "`+d+`" accept`,                 // same network (br_netfilter)
			`iifname "`+d+`" oifname `+lans+` accept`,                // containers -> LAN segments
			`iifname "`+d+`" oifname "wlp2s0" accept`,                // containers -> WAN
			`iifname `+lans+` oifname "`+d+`" ct status dnat accept`, // LAN -> published ports only
			`iifname "wlp2s0" oifname "`+d+`" ct status dnat accept`, // WAN -> published ports only
		)
	}
}

func TestDockerPublishedPortsAreTheOnlyWayIn(t *testing.T) {
	out := mustRender(t, dockerSnap(nil))
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `oifname "docker0"`) || strings.Contains(line, `oifname "br-*"`) {
			if strings.Contains(line, `iifname "wlp2s0"`) && !strings.Contains(line, "ct status dnat") {
				t.Errorf("WAN may reach a container without going through a published port: %s", line)
			}
			if strings.Contains(line, "enp1s0") && strings.Contains(line, "iifname {") && !strings.Contains(line, "ct status dnat") {
				t.Errorf("a LAN may reach a container without going through a published port: %s", line)
			}
		}
	}
}

func TestDockerWANSourceLimitsPublishedPortsOnly(t *testing.T) {
	out := mustRender(t, dockerSnap(func(s *config.Snapshot) { s.DockerWANSource = "192.168.1.20" }))
	requireContains(t, out, `iifname "wlp2s0" oifname "docker0" ip saddr 192.168.1.20 ct status dnat accept`)
	// the LAN side is trusted and not restricted by it
	requireContains(t, out, `oifname "docker0" ct status dnat accept`)
	if strings.Contains(out, `iifname { "enp1s0", "enp1s0.20" } oifname "docker0" ip saddr`) {
		t.Error("the WAN source limit leaked onto the LAN rule")
	}
}

func TestDockerCustomInterfacesReplaceTheDefaults(t *testing.T) {
	out := mustRender(t, dockerSnap(func(s *config.Snapshot) { s.DockerInterfaces = []string{" mybridge ", "docker0", "docker0"} }))
	requireContains(t, out, `iifname "mybridge" accept`, `iifname "docker0" accept`)
	if strings.Contains(out, `"br-*"`) {
		t.Error("default br-* leaked in despite a custom list")
	}
	if n := strings.Count(out, `iifname "docker0" accept`); n != 1 {
		t.Errorf("duplicate pattern rendered %d times", n)
	}
}

func TestDockerRejectsInterfacesThatWouldTrustTheWANOrALAN(t *testing.T) {
	cases := map[string]func(*config.Snapshot){
		"wan matched by wildcard": func(s *config.Snapshot) { s.DockerInterfaces = []string{"wl*"} },
		"wan named like a bridge": func(s *config.Snapshot) { s.WANInterface = "br-uplink" }, // default br-* now covers the WAN
		"lan named like a bridge": func(s *config.Snapshot) { s.LANSegments[0].Interface = "br-lan" },
		"bare star":               func(s *config.Snapshot) { s.DockerInterfaces = []string{"*"} },
		"loopback":                func(s *config.Snapshot) { s.DockerInterfaces = []string{"lo"} },
		"wan exactly":             func(s *config.Snapshot) { s.DockerInterfaces = []string{"wlp2s0"} },
		"lan vlan via prefix":     func(s *config.Snapshot) { s.DockerInterfaces = []string{"enp1s0.*"} },
		"star in the middle":      func(s *config.Snapshot) { s.DockerInterfaces = []string{"br*x"} },
		"quote breaks out":        func(s *config.Snapshot) { s.DockerInterfaces = []string{`docker0" accept; flush ruleset; "`} },
		"space":                   func(s *config.Snapshot) { s.DockerInterfaces = []string{"docker 0"} },
		"too long":                func(s *config.Snapshot) { s.DockerInterfaces = []string{"abcdefghijklmnop"} },
		"only blanks":             func(s *config.Snapshot) { s.DockerInterfaces = []string{" ", ""}; s.WANInterface = "br-uplink" },
		"bad source":              func(s *config.Snapshot) { s.DockerWANSource = "10.0.0.0/33" },
		"source with nft syntax":  func(s *config.Snapshot) { s.DockerWANSource = "1.2.3.4 accept; flush ruleset" },
		"ipv6 source":             func(s *config.Snapshot) { s.DockerWANSource = "fe80::1" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			snap := dockerSnap(mut)
			if out, err := Render(snap); err == nil {
				t.Fatalf("expected an error, got a ruleset:\n%s", out)
			}
			if err := ValidateDocker(snap); err == nil {
				t.Fatalf("ValidateDocker accepted it")
			}
		})
	}
}

func TestPatternsOverlap(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"br-*", "br-lan", true}, {"br-*", "br-*", true}, {"br-*", "b*", true}, {"b*", "br-*", true},
		{"br-*", "docker0", false}, {"docker0", "docker0", true}, {"docker0", "docker1", false},
		{"enp1s0.*", "enp1s0", false}, {"enp1s0.*", "enp1s0.20", true}, {"wl*", "wlp2s0", true},
		{"br-*", "eth0", false},
	} {
		if got := patternsOverlap(c.a, c.b); got != c.want {
			t.Errorf("patternsOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := patternsOverlap(c.b, c.a); got != c.want {
			t.Errorf("patternsOverlap(%q, %q) = %v, want %v (not symmetric)", c.b, c.a, got, c.want)
		}
	}
}

func TestDockerWarnsWhenAnySourceMayReachPublishedPorts(t *testing.T) {
	has := func(snap config.Snapshot) bool {
		for _, w := range Warnings(snap) {
			if strings.Contains(w, "published ports") {
				return true
			}
		}
		return false
	}
	if !has(dockerSnap(nil)) {
		t.Error("expected a warning when Docker is on with no source limit")
	}
	if has(dockerSnap(func(s *config.Snapshot) { s.DockerWANSource = "192.168.1.20" })) {
		t.Error("warned even though a source limit is set")
	}
	if has(testSnap()) {
		t.Error("warned about Docker while Docker is off")
	}
}

// Shapes taken from `nft -j list chains` on a box running Docker's iptables-nft backend,
// Docker's own nftables backend, and a plain hand-written router.
const (
	jsonDockerIptablesNft = `{"nftables":[{"metainfo":{"version":"1.0.9"}},
	 {"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":1,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
	 {"chain":{"family":"ip","table":"filter","name":"DOCKER-USER","handle":2}},
	 {"chain":{"family":"ip","table":"filter","name":"DOCKER","handle":3}},
	 {"chain":{"family":"ip","table":"filter","name":"INPUT","handle":4,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
	 {"chain":{"family":"ip","table":"nat","name":"PREROUTING","handle":5,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}},
	 {"chain":{"family":"inet","table":"cobweb","name":"forward","handle":6,"type":"filter","hook":"forward","prio":0,"policy":"drop"}}]}`
	jsonDockerNoDrop = `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
	 {"chain":{"family":"ip","table":"filter","name":"DOCKER","handle":3}}]}`
	jsonDockerNativeBackend = `{"nftables":[
	 {"chain":{"family":"ip","table":"docker-bridges","name":"filter-FORWARD","type":"filter","hook":"forward","prio":0,"policy":"accept"}}]}`
	jsonHandWrittenRouter = `{"nftables":[
	 {"chain":{"family":"inet","table":"filter","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
	 {"chain":{"family":"ip","table":"nat","name":"postrouting","type":"nat","hook":"postrouting","prio":100,"policy":"accept"}}]}`
)

func TestParseEnvironment(t *testing.T) {
	env := parseEnvironment(jsonDockerIptablesNft)
	if !env.DockerDetected || len(env.DockerForwardDrops) != 1 || env.DockerForwardDrops[0] != "ip filter FORWARD" {
		t.Errorf("Docker + drop policy not recognised: %+v", env)
	}
	if len(env.ForwardDrops) != 1 {
		t.Errorf("cobweb's own forward chain must be ignored, got %v", env.ForwardDrops)
	}

	env = parseEnvironment(jsonDockerNoDrop)
	if !env.DockerDetected || len(env.ForwardDrops) != 0 || len(env.DockerForwardDrops) != 0 {
		t.Errorf("ip-forward-no-drop setup flagged: %+v", env)
	}

	env = parseEnvironment(jsonDockerNativeBackend)
	if !env.DockerDetected || len(env.ForwardDrops) != 0 {
		t.Errorf("docker's nftables backend not recognised, or wrongly flagged: %+v", env)
	}

	// An old hand-written router has a legitimate drop policy: reported as a forward-drop
	// table, but never accused of being Docker.
	env = parseEnvironment(jsonHandWrittenRouter)
	if env.DockerDetected || len(env.DockerForwardDrops) != 0 || len(env.ForwardDrops) != 1 {
		t.Errorf("hand-written router misclassified: %+v", env)
	}

	for _, junk := range []string{"", "not json", "{}", `{"nftables":null}`, `{"nftables":[{"chain":null}]}`} {
		if env := parseEnvironment(junk); env.DockerDetected || len(env.ForwardDrops) != 0 {
			t.Errorf("junk %q produced %+v", junk, env)
		}
	}
}

func TestDetectEnvironmentWithoutNft(t *testing.T) {
	old := outputFn
	defer func() { outputFn = old }()
	outputFn = func(string, ...string) (string, error) { return "", errors.New("nft: not found") }
	if env := DetectEnvironment(); env.DockerDetected || len(env.ForwardDrops) != 0 {
		t.Errorf("expected zero Environment, got %+v", env)
	}
}

// If nft is here and we may use it, the Docker ruleset must at least pass nft's own syntax
// check (the lab scenarios exercise it for real).
func TestDockerRulesetPassesRealNftSyntaxCheck(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for nft -c")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(mustRender(t, dockerSnap(func(s *config.Snapshot) { s.DockerWANSource = "192.168.1.0/24" })))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("nft -c unavailable here (%v: %s)", err, out) // e.g. no CAP_NET_ADMIN in this sandbox
	}
}

func trustedSnap(patterns ...string) config.Snapshot {
	snap := testSnap()
	snap.TrustedInterfaces = patterns
	return snap
}

func TestTrustedOffRendersExactlyTheBaseline(t *testing.T) {
	if a, b := mustRender(t, trustedSnap()), mustRender(t, testSnap()); a != b {
		t.Fatalf("empty trusted list changed the ruleset:\n%s", a)
	}
	if strings.Contains(mustRender(t, testSnap()), "trusted") {
		t.Fatal("baseline ruleset mentions trusted interfaces")
	}
}

func TestTrustedRulesRendered(t *testing.T) {
	out := mustRender(t, trustedSnap("wg0"))
	requireContains(t, out,
		`iifname "wg0" accept comment "trusted interface: may talk to the router"`,
		`iifname "wg0" oifname { "enp1s0", "enp1s0.20" } accept`,
		`iifname "wg0" oifname "wlp2s0" accept`,
	)
	// Nothing may start a new connection toward the VPN.
	if strings.Contains(out, `oifname "wg0"`) {
		t.Fatalf("a rule allows traffic toward the trusted interface:\n%s", out)
	}
	// Docker is off, so no dnat rule to bridges.
	if strings.Contains(out, "ct status dnat") {
		t.Fatalf("unexpected dnat rule:\n%s", out)
	}
}

func TestTrustedWildcardAndDocker(t *testing.T) {
	snap := dockerSnap(func(s *config.Snapshot) { s.TrustedInterfaces = []string{"wg*"} })
	out := mustRender(t, snap)
	requireContains(t, out,
		`iifname "wg*" oifname "docker0" ct status dnat accept`,
		`iifname "wg*" oifname "br-*" ct status dnat accept`,
	)
}

func TestTrustedRejectsDangerousPatterns(t *testing.T) {
	for _, bad := range []string{"wlp2s0", "wlp*", "enp1s0", "enp1s0.20", "enp*", "lo", "*", "l*", "wg 0", `wg0"`, "a;b"} {
		if err := ValidateTrusted(trustedSnap(bad)); err == nil {
			t.Errorf("trusted pattern %q accepted", bad)
		}
		if _, err := Render(trustedSnap(bad)); err == nil {
			t.Errorf("Render accepted trusted pattern %q", bad)
		}
	}
}

func TestTrustedAndDockerCannotOverlap(t *testing.T) {
	// Only when Docker is enabled: otherwise the setting has no effect.
	dock := func(trusted, bridges []string) config.Snapshot {
		return dockerSnap(func(s *config.Snapshot) { s.TrustedInterfaces = trusted; s.DockerInterfaces = bridges })
	}
	for _, c := range []struct{ trusted, bridges []string }{
		{[]string{"br-*"}, nil},
		{[]string{"docker0"}, nil},
		{[]string{"br-vpn"}, nil},
		{[]string{"wg0"}, []string{"wg*"}},
	} {
		if _, err := Render(dock(c.trusted, c.bridges)); err == nil {
			t.Errorf("overlap accepted: trusted=%v docker=%v", c.trusted, c.bridges)
		}
	}
	s := testSnap()
	s.TrustedInterfaces = []string{"br-vpn"}
	s.DockerInterfaces = []string{"br-*"} // docker disabled
	if _, err := Render(s); err != nil {
		t.Errorf("overlap with a disabled Docker feature should be allowed: %v", err)
	}
}

func TestTrustedDedupeAndBlank(t *testing.T) {
	got, err := TrustedInterfaces(trustedSnap(" wg0 ", "", "wg0", "wg1"))
	if err != nil || len(got) != 2 || got[0] != "wg0" || got[1] != "wg1" {
		t.Fatalf("got %v, %v", got, err)
	}
}
