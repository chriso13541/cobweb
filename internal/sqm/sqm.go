// Package sqm applies Smart Queue Management to cobweb's WAN link,
// specifically to fight bufferbloat: without it, a single saturating
// flow (a big download, a backup, anything bulk) can queue up enough
// data that latency-sensitive traffic sharing the same link - a game,
// a video call - gets stuck waiting behind it, even though those
// packets are tiny and would take no time to send on their own.
//
// The actual mechanism is Linux's own cake qdisc (Common Applications
// Kept Enhanced): fair queuing keeps one flow from monopolizing the
// link, and active queue management keeps the queue itself shallow
// rather than letting it balloon. cobweb doesn't reimplement any of
// this - it just drives the standard `tc` tooling already present on
// any normal Linux install, the same way nftables is left to handle
// firewall/NAT rather than being reimplemented in Go.
//
// Upload shaping is a direct qdisc on the WAN interface's own egress.
// Download shaping is trickier: tc can only shape a device's outbound
// traffic, not inbound - so limiting download speed means mirroring
// the WAN interface's *inbound* traffic onto a virtual IFB
// (Intermediate Functional Block) device via a redirect filter, then
// shaping that IFB device's egress instead. This is the standard,
// well-established trick for this - not a workaround unique to
// cobweb.
package sqm

import (
	"fmt"
	"os/exec"
	"strings"
)

// Config is the desired shaping state for the WAN link.
type Config struct {
	Enabled      bool
	WANInterface string
	DownloadMbit int
	UploadMbit   int
}

// runFn is a seam for tests: production code shells out to the real
// tc/ip/modprobe binaries. Tests substitute a fake that records which
// commands would have run, without needing actual kernel qdisc
// support - useful since not every environment (including some
// minimal/containerized ones) has the cake or ifb kernel modules
// available, and the command-construction logic is what's actually
// worth testing in isolation from that.
var runFn = func(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

const ifbDevice = "ifb0"

// Apply configures upload and download shaping on the WAN interface.
// Safe to call repeatedly (uses "replace" throughout, not "add") -
// reapplying with new bandwidth numbers just updates the existing
// configuration rather than erroring on something already present.
func Apply(cfg Config) error {
	if !cfg.Enabled {
		return Remove(cfg.WANInterface)
	}
	if cfg.WANInterface == "" {
		return fmt.Errorf("sqm: no WAN interface configured")
	}
	if cfg.DownloadMbit <= 0 || cfg.UploadMbit <= 0 {
		return fmt.Errorf("sqm: download and upload limits must both be positive (got %d/%d)", cfg.DownloadMbit, cfg.UploadMbit)
	}

	if err := runFn("modprobe", "ifb", "numifbs=1"); err != nil {
		return fmt.Errorf("sqm: load ifb kernel module (try 'sudo modprobe ifb' manually to see the real error): %w", err)
	}
	// numifbs only controls auto-created devices the very first time
	// the module is inserted - if ifb was already loaded from an
	// earlier manual test (or anything else), that modprobe call
	// above is a silent no-op regardless of numifbs, and no device
	// may exist at all. Creating it explicitly by name works
	// regardless of module load history; "File exists" just means a
	// previous run (or the module itself) already created it, which
	// is fine, not a real failure.
	if err := runFn("ip", "link", "add", ifbDevice, "type", "ifb"); err != nil && !strings.Contains(err.Error(), "File exists") {
		return fmt.Errorf("sqm: create %s device: %w", ifbDevice, err)
	}
	if err := runFn("ip", "link", "set", "dev", ifbDevice, "up"); err != nil {
		return fmt.Errorf("sqm: bring up %s: %w", ifbDevice, err)
	}

	// Upload: shape the WAN interface's own egress directly.
	if err := runFn("tc", "qdisc", "replace", "dev", cfg.WANInterface, "root", "cake",
		"bandwidth", fmt.Sprintf("%dmbit", cfg.UploadMbit)); err != nil {
		return fmt.Errorf("sqm: apply upload shaping (is the cake qdisc available? try 'sudo modprobe sch_cake'): %w", err)
	}

	// Download: redirect the WAN interface's ingress onto the IFB
	// device, then shape THAT device's egress instead.
	if err := runFn("tc", "qdisc", "replace", "dev", cfg.WANInterface, "handle", "ffff:", "ingress"); err != nil {
		return fmt.Errorf("sqm: add ingress qdisc: %w", err)
	}
	if err := runFn("tc", "filter", "replace", "dev", cfg.WANInterface, "parent", "ffff:",
		"matchall", "action", "mirred", "egress", "redirect", "dev", ifbDevice); err != nil {
		return fmt.Errorf("sqm: redirect ingress traffic to %s: %w", ifbDevice, err)
	}
	if err := runFn("tc", "qdisc", "replace", "dev", ifbDevice, "root", "cake",
		"bandwidth", fmt.Sprintf("%dmbit", cfg.DownloadMbit)); err != nil {
		return fmt.Errorf("sqm: apply download shaping: %w", err)
	}

	return nil
}

// Remove tears down all shaping. Safe to call even if nothing was
// ever applied - tc's own "no such qdisc" errors on a never-shaped
// interface are expected, not treated as failures.
func Remove(wanInterface string) error {
	if wanInterface == "" {
		return nil
	}
	_ = runFn("tc", "qdisc", "del", "dev", wanInterface, "root")
	_ = runFn("tc", "qdisc", "del", "dev", wanInterface, "ingress")
	_ = runFn("tc", "qdisc", "del", "dev", ifbDevice, "root")
	_ = runFn("ip", "link", "del", ifbDevice)
	return nil
}
