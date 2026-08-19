package sqm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// recordedCommand captures one call through runFn for assertions.
type recordedCommand struct {
	name string
	args []string
}

func withRecordedCommands(t *testing.T) *[]recordedCommand {
	t.Helper()
	var calls []recordedCommand
	old := runFn
	runFn = func(name string, args ...string) error {
		calls = append(calls, recordedCommand{name: name, args: args})
		return nil
	}
	t.Cleanup(func() { runFn = old })
	return &calls
}

func TestApplyGeneratesCorrectCommandSequence(t *testing.T) {
	calls := withRecordedCommands(t)

	cfg := Config{Enabled: true, WANInterface: "wlp2s0", DownloadMbit: 190, UploadMbit: 200}
	if err := Apply(cfg); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// The exact sequence matters here: ifb must be loaded, explicitly
	// created by name (not just relying on numifbs, which is only
	// honored on the module's first-ever load), and brought up before
	// anything references it; upload shaping is independent; download
	// shaping must set up the ingress qdisc and redirect filter before
	// the final cake qdisc on the ifb device.
	want := []recordedCommand{
		{"modprobe", []string{"ifb", "numifbs=1"}},
		{"ip", []string{"link", "add", "ifb0", "type", "ifb"}},
		{"ip", []string{"link", "set", "dev", "ifb0", "up"}},
		{"tc", []string{"qdisc", "replace", "dev", "wlp2s0", "root", "cake", "bandwidth", "200mbit"}},
		{"tc", []string{"qdisc", "replace", "dev", "wlp2s0", "handle", "ffff:", "ingress"}},
		{"tc", []string{"filter", "replace", "dev", "wlp2s0", "parent", "ffff:", "matchall", "action", "mirred", "egress", "redirect", "dev", "ifb0"}},
		{"tc", []string{"qdisc", "replace", "dev", "ifb0", "root", "cake", "bandwidth", "190mbit"}},
	}

	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("command sequence mismatch\ngot:  %+v\nwant: %+v", *calls, want)
	}
}

func TestApplyTreatsFileExistsAsHarmless(t *testing.T) {
	// Reproduces the actual reported bug's root cause: if ifb0 (or the
	// module itself) is already present from an earlier manual test or
	// a previous Apply call, "ip link add ifb0 type ifb" fails with
	// "File exists" - that must NOT be treated as a real failure, or
	// every subsequent Apply call after the first would incorrectly
	// error out forever.
	old := runFn
	var sawBringUp bool
	runFn = func(name string, args ...string) error {
		if name == "ip" && len(args) >= 2 && args[0] == "link" && args[1] == "add" {
			return errors.New("RTNETLINK answers: File exists")
		}
		if name == "ip" && len(args) >= 2 && args[0] == "link" && args[1] == "set" {
			sawBringUp = true
		}
		return nil
	}
	t.Cleanup(func() { runFn = old })

	err := Apply(Config{Enabled: true, WANInterface: "wlp2s0", DownloadMbit: 190, UploadMbit: 200})
	if err != nil {
		t.Fatalf("Apply should tolerate 'File exists' on ifb0 creation, got: %v", err)
	}
	if !sawBringUp {
		t.Fatal("expected Apply to still proceed to bringing the device up after tolerating 'File exists'")
	}
}

func TestApplyRejectsMissingWANInterface(t *testing.T) {
	withRecordedCommands(t)
	err := Apply(Config{Enabled: true, WANInterface: "", DownloadMbit: 100, UploadMbit: 100})
	if err == nil || !strings.Contains(err.Error(), "no WAN interface") {
		t.Fatalf("expected a clear 'no WAN interface' error, got: %v", err)
	}
}

func TestApplyRejectsNonPositiveBandwidth(t *testing.T) {
	withRecordedCommands(t)
	cases := []Config{
		{Enabled: true, WANInterface: "wlp2s0", DownloadMbit: 0, UploadMbit: 100},
		{Enabled: true, WANInterface: "wlp2s0", DownloadMbit: 100, UploadMbit: 0},
		{Enabled: true, WANInterface: "wlp2s0", DownloadMbit: -5, UploadMbit: 100},
	}
	for _, cfg := range cases {
		if err := Apply(cfg); err == nil {
			t.Errorf("expected an error for %+v, got nil - shaping to zero/negative would effectively kill the link", cfg)
		}
	}
}

func TestApplyWithDisabledConfigCallsRemove(t *testing.T) {
	calls := withRecordedCommands(t)
	if err := Apply(Config{Enabled: false, WANInterface: "wlp2s0"}); err != nil {
		t.Fatalf("Apply with Enabled=false should tear down, not error: %v", err)
	}
	// Should have gone through Remove's teardown commands, not Apply's
	// setup commands (no modprobe/redirect - those are shaping setup).
	for _, c := range *calls {
		if c.name == "modprobe" {
			t.Fatal("Apply(Enabled: false) should tear down existing shaping, not try to set new shaping up")
		}
	}
	if len(*calls) == 0 {
		t.Fatal("expected teardown commands to run")
	}
}

func TestRemoveIsSafeWithNothingToRemove(t *testing.T) {
	withRecordedCommands(t)
	old := runFn
	runFn = func(name string, args ...string) error {
		return errors.New("no such qdisc") // simulates tc's real behavior on a never-shaped interface
	}
	t.Cleanup(func() { runFn = old })

	if err := Remove("wlp2s0"); err != nil {
		t.Fatalf("Remove should tolerate 'nothing to remove' errors, got: %v", err)
	}
}

func TestRemoveWithEmptyInterfaceIsNoOp(t *testing.T) {
	calls := withRecordedCommands(t)
	if err := Remove(""); err != nil {
		t.Fatalf("Remove(\"\") should be a safe no-op, got: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no commands for an empty interface, got: %+v", *calls)
	}
}
