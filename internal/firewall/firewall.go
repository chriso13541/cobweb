// Package firewall turns cobweb's port rules into an nftables ruleset
// and applies it.
//
// When enabled, cobweb owns two nftables tables outright - "inet
// cobweb" (filtering) and "ip cobweb_nat" (DNAT + masquerade) - and
// replaces them atomically on every change. It never touches any other
// table. That has one consequence worth knowing: nftables evaluates
// every base chain registered at a hook, and a packet has to be
// accepted by all of them, so an "accept" in cobweb's table cannot
// override a "policy drop" in some other table at the same hook. Moving
// to a cobweb-managed firewall therefore means retiring the old
// hand-written ruleset; ForeignTables exists so the dashboard can say so
// when it spots leftovers.
//
// Safety properties:
//   - Every value written into the ruleset is re-derived from a parsed
//     form (net.IP, ints, a protocol whitelist, a character-filtered
//     comment), never copied from the config string. A hand-edited or
//     imported config can't smuggle extra nft commands in.
//   - The ruleset is syntax-checked with `nft -c` before being applied,
//     and `nft -f` applies it as one transaction, so a bad ruleset leaves
//     the previous state in place instead of half-applied.
//   - The whole thing is off unless config.FirewallEnabled is set.
package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"cobweb/internal/config"
)

const (
	filterTable = "inet cobweb"
	natTable    = "ip cobweb_nat"
)

// ifaceRe is deliberately stricter than what Linux allows in an
// interface name: no quotes, backslashes, whitespace or anything else
// that could break out of the quoted string it's written into.
var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// runFn is a seam for tests: production code pipes the ruleset to the
// real nft binary on stdin.
var runFn = func(stdin, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// outputFn is a seam for tests: runs a command and returns its stdout.
var outputFn = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

// enableForwardingFn is a seam for tests. DNAT and routing both need
// IPv4 forwarding on; a router normally has it already, but a firewall
// cobweb manages shouldn't silently depend on that.
var enableForwardingFn = func() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

// --- parsing / validation ---

type portSpec struct{ lo, hi int }

func (p portSpec) isRange() bool { return p.lo != p.hi }

func (p portSpec) String() string {
	if p.lo == p.hi {
		return strconv.Itoa(p.lo)
	}
	return fmt.Sprintf("%d-%d", p.lo, p.hi)
}

func (p portSpec) contains(port int) bool { return p.lo <= port && port <= p.hi }

func parseSinglePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("port is empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q isn't a valid port number", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q isn't a valid port number (1-65535)", s)
	}
	return n, nil
}

// parsePortSpec accepts "445" or an inclusive range like "8000-8010".
func parsePortSpec(s string) (portSpec, error) {
	s = strings.TrimSpace(s)
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := parseSinglePort(lo)
	if err != nil {
		return portSpec{}, err
	}
	if !isRange {
		return portSpec{a, a}, nil
	}
	b, err := parseSinglePort(hi)
	if err != nil {
		return portSpec{}, err
	}
	if a > b {
		return portSpec{}, fmt.Errorf("port range %q runs backwards", s)
	}
	return portSpec{a, b}, nil
}

// parseSource normalizes an optional IPv4 address or CIDR. A CIDR with
// host bits set (192.168.1.5/24) is rejected rather than silently
// widened to the whole network - this is an allowlist, and quietly
// allowing 254 more hosts than the person typed would be the wrong
// failure mode.
func parseSource(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "/") {
		ip, n, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return "", fmt.Errorf("source %q isn't a valid IPv4 address or CIDR", s)
		}
		if !ip.Equal(n.IP) {
			return "", fmt.Errorf("source %q has host bits set; did you mean %s (the whole network) or %s (just that host)?", s, n.String(), ip.To4().String())
		}
		return n.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("source %q isn't a valid IPv4 address or CIDR", s)
	}
	return ip.To4().String(), nil
}

func parseProtocols(s string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return []string{"tcp"}, nil
	case "udp":
		return []string{"udp"}, nil
	case "both":
		return []string{"tcp", "udp"}, nil
	}
	return nil, fmt.Errorf("protocol %q must be tcp, udp, or both", s)
}

// sanitizeComment keeps only characters that are safe inside a quoted
// nft comment, and caps the length. The result is purely cosmetic - it
// shows up in `nft list ruleset` so a rule can be traced back to its
// name.
func sanitizeComment(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
		if b.Len() >= 40 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func segmentContaining(segments []config.LANSegment, ip net.IP) (config.LANSegment, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return config.LANSegment{}, false
	}
	for _, s := range segments {
		addr := net.ParseIP(s.Address).To4()
		mask := net.ParseIP(s.SubnetMask).To4()
		if addr == nil || mask == nil {
			continue
		}
		m := net.IPMask(mask)
		if addr.Mask(m).Equal(ip4.Mask(m)) {
			return s, true
		}
	}
	return config.LANSegment{}, false
}

// parsedRule is a PortRule with every field parsed and normalized -
// the only form Render ever writes from.
type parsedRule struct {
	name      string
	kind      string
	protos    []string
	port      portSpec
	toIP      net.IP
	toPort    portSpec
	hasToPort bool
	source    string
}

// postNATPort is the destination port as seen in the forward chain,
// i.e. after DNAT has already rewritten it.
func (p parsedRule) postNATPort() portSpec {
	if p.hasToPort {
		return p.toPort
	}
	return p.port
}

func normalize(r config.PortRule, segments []config.LANSegment) (parsedRule, error) {
	var p parsedRule
	p.name = sanitizeComment(r.Name)

	p.kind = strings.ToLower(strings.TrimSpace(r.Kind))
	if p.kind != config.RuleForward && p.kind != config.RuleInput {
		return p, fmt.Errorf("type must be %q or %q", config.RuleForward, config.RuleInput)
	}

	var err error
	if p.protos, err = parseProtocols(r.Protocol); err != nil {
		return p, err
	}
	if p.port, err = parsePortSpec(r.Port); err != nil {
		return p, err
	}
	if p.source, err = parseSource(r.Source); err != nil {
		return p, err
	}

	if p.kind == config.RuleInput {
		return p, nil
	}

	ip := net.ParseIP(strings.TrimSpace(r.ToIP))
	if ip == nil || ip.To4() == nil {
		return p, fmt.Errorf("target %q isn't a valid IPv4 address", r.ToIP)
	}
	p.toIP = ip.To4()
	seg, ok := segmentContaining(segments, p.toIP)
	if !ok {
		return p, fmt.Errorf("target %s isn't inside any configured LAN segment", p.toIP)
	}
	if p.toIP.Equal(net.ParseIP(seg.Address)) {
		return p, fmt.Errorf("target %s is this router's own address on %q; use an \"input\" rule to expose a service running on this box", p.toIP, seg.Name)
	}
	if strings.TrimSpace(r.ToPort) != "" {
		if p.port.isRange() {
			return p, fmt.Errorf("a port range can't be remapped to a different port; leave the target port blank to keep ports unchanged")
		}
		n, err := parseSinglePort(r.ToPort)
		if err != nil {
			return p, fmt.Errorf("target port: %w", err)
		}
		p.toPort = portSpec{n, n}
		p.hasToPort = true
	}
	return p, nil
}

// Validate checks one rule on its own, including that a forward
// target sits inside one of the configured LAN segments.
func Validate(r config.PortRule, segments []config.LANSegment) error {
	_, err := normalize(r, segments)
	return err
}

// --- rendering ---

func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

// Render builds the full nftables ruleset text for snap. It renders
// regardless of snap.FirewallEnabled, so it can be used to preview
// (`cobweb --print-firewall`) before switching anything on.
func Render(snap config.Snapshot) (string, error) {
	wan := strings.TrimSpace(snap.WANInterface)
	if !ifaceRe.MatchString(wan) {
		return "", fmt.Errorf("firewall: WAN interface %q isn't a valid interface name", snap.WANInterface)
	}

	var lans []string
	seen := map[string]bool{}
	for _, seg := range snap.LANSegments {
		name := strings.TrimSpace(seg.Interface)
		if !ifaceRe.MatchString(name) {
			return "", fmt.Errorf("firewall: segment %q has an invalid interface name %q", seg.Name, seg.Interface)
		}
		if name == wan {
			return "", fmt.Errorf("firewall: segment %q uses the WAN interface %q as its LAN interface", seg.Name, wan)
		}
		if !seen[name] {
			seen[name] = true
			lans = append(lans, name)
		}
	}
	if len(lans) == 0 {
		return "", fmt.Errorf("firewall: no LAN segments configured")
	}
	lanSet := quoteList(lans)

	var inputRules, forwardRules, dnatRules []string
	for _, r := range snap.PortRules {
		if r.Disabled {
			continue
		}
		p, err := normalize(r, snap.LANSegments)
		if err != nil {
			label := r.Name
			if label == "" {
				label = r.ID
			}
			return "", fmt.Errorf("firewall: rule %q: %w", label, err)
		}

		src := ""
		if p.source != "" {
			src = "ip saddr " + p.source + " "
		}
		comment := ""
		if p.name != "" {
			comment = ` comment "` + p.name + `"`
		}

		for _, proto := range p.protos {
			switch p.kind {
			case config.RuleInput:
				inputRules = append(inputRules, fmt.Sprintf(`iifname "%s" %s%s dport %s accept%s`, wan, src, proto, p.port, comment))
			case config.RuleForward:
				forwardRules = append(forwardRules, fmt.Sprintf(`iifname "%s" %sip daddr %s %s dport %s accept%s`, wan, src, p.toIP, proto, p.postNATPort(), comment))
				target := p.toIP.String()
				if p.hasToPort {
					target += ":" + p.toPort.String()
				}
				dnatRules = append(dnatRules, fmt.Sprintf(`iifname "%s" fib daddr type local %s%s dport %s dnat to %s%s`, wan, src, proto, p.port, target, comment))
			}
		}
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Generated by cobweb - edit rules in the dashboard (Settings -> Firewall), not here.")
	w("# Declaring then deleting each table first makes this safe to apply whether or")
	w("# not it already exists, and nft applies the whole file as one transaction.")
	w("table %s", filterTable)
	w("delete table %s", filterTable)
	w("table %s", natTable)
	w("delete table %s", natTable)
	w("")
	w("table %s {", filterTable)
	w("    chain input {")
	w("        type filter hook input priority 0; policy drop;")
	w(`        iifname "lo" accept`)
	w("        ct state established,related accept")
	w("        ct state invalid drop")
	w("        # ICMP (1) and ICMPv6 (58): ping, path-MTU discovery, IPv6 neighbor discovery")
	w("        meta l4proto { 1, 58 } accept")
	w("        # Everything on a LAN segment may talk to the router itself (DHCP, DNS, dashboard, SSH).")
	w("        iifname %s accept", lanSet)
	for _, r := range inputRules {
		w("        %s", r)
	}
	w("    }")
	w("    chain forward {")
	w("        type filter hook forward priority 0; policy drop;")
	w("        ct state established,related accept")
	w("        ct state invalid drop")
	w("        # LAN segments route freely between each other and out to the WAN.")
	w("        iifname %s oifname %s accept", lanSet, lanSet)
	w(`        iifname %s oifname "%s" accept`, lanSet, wan)
	for _, r := range forwardRules {
		w("        %s", r)
	}
	w("    }")
	w("}")
	w("")
	w("table %s {", natTable)
	w("    chain prerouting {")
	w("        type nat hook prerouting priority -100; policy accept;")
	for _, r := range dnatRules {
		w("        %s", r)
	}
	w("    }")
	w("    chain postrouting {")
	w("        type nat hook postrouting priority 100; policy accept;")
	w(`        oifname "%s" masquerade`, wan)
	w("    }")
	w("}")

	return b.String(), nil
}

// Warnings returns human-readable heads-ups about the current rule set -
// things that are legal but probably not what the person meant.
func Warnings(snap config.Snapshot) []string {
	var out []string

	sshAllowed := false
	for _, r := range snap.PortRules {
		if r.Disabled || strings.ToLower(strings.TrimSpace(r.Kind)) != config.RuleInput {
			continue
		}
		protos, err := parseProtocols(r.Protocol)
		if err != nil {
			continue
		}
		port, err := parsePortSpec(r.Port)
		if err != nil {
			continue
		}
		for _, p := range protos {
			if p == "tcp" && port.contains(22) {
				sshAllowed = true
			}
		}
	}
	if !sshAllowed {
		out = append(out, "No rule allows SSH (tcp 22) from the WAN side. If you administer this box over the house network (e.g. through a bastion host), add an \"input\" rule for tcp 22 before enabling the firewall, or you'll lock yourself out. Access from the LAN segments is never blocked.")
	}

	for _, r := range snap.PortRules {
		if r.Disabled || strings.TrimSpace(r.Source) != "" {
			continue
		}
		label := r.Name
		if label == "" {
			label = r.ID
		}
		out = append(out, fmt.Sprintf("Rule %q accepts traffic from any address on the WAN side. If that network is reachable from the internet, set a Source to limit who can use it.", label))
	}
	return out
}

// ForeignTables lists nftables tables that cobweb doesn't own (e.g. an
// old hand-written "inet filter"). While they exist, their chains are
// still evaluated alongside cobweb's, so a leftover "policy drop"
// there can block traffic cobweb's rules allow. Returns nil if nft isn't
// available or has nothing else loaded.
func ForeignTables() []string {
	out, err := outputFn("nft", "list", "tables")
	if err != nil {
		return nil
	}
	var foreign []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "table ") {
			continue
		}
		name := strings.TrimPrefix(line, "table ")
		if name == filterTable || name == natTable {
			continue
		}
		foreign = append(foreign, name)
	}
	return foreign
}

// --- applying ---

// Apply makes the kernel match snap: if the firewall is enabled, it
// renders, syntax-checks, then atomically installs the ruleset; if it's
// disabled, it removes cobweb's tables (and only cobweb's).
func Apply(snap config.Snapshot) error {
	if !snap.FirewallEnabled {
		return Remove()
	}
	ruleset, err := Render(snap)
	if err != nil {
		return err
	}
	if err := runFn(ruleset, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("firewall: the generated ruleset failed nft's syntax check, so nothing was changed: %w", err)
	}
	if err := runFn(ruleset, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("firewall: apply ruleset: %w", err)
	}
	if err := enableForwardingFn(); err != nil {
		log.Printf("firewall: ruleset applied, but couldn't enable net.ipv4.ip_forward (set it yourself if forwarding doesn't work): %v", err)
	}
	return nil
}

const teardown = "table " + filterTable + "\ndelete table " + filterTable + "\ntable " + natTable + "\ndelete table " + natTable + "\n"

// Remove deletes cobweb's tables. Safe to call when they don't exist.
func Remove() error {
	if err := runFn(teardown, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("firewall: remove cobweb tables: %w", err)
	}
	return nil
}
