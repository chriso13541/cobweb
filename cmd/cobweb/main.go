// Command cobweb is a self-contained home-router control plane: a
// DHCP server, a DNS server, and a web dashboard, all driven by one
// JSON config file. There is no dependency on dnsmasq or any other
// external daemon - everything network-facing that cobweb does, it
// does itself, and every setting is editable from the dashboard rather
// than by hand-editing config files scattered across the system.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"cobweb/internal/auth"
	"cobweb/internal/config"
	"cobweb/internal/dhcp"
	"cobweb/internal/dnsserver"
	"cobweb/internal/firewall"
	"cobweb/internal/sqm"
	"cobweb/internal/web"
)

func main() {
	configPath := flag.String("config", "/etc/cobweb/config.json", "path to cobweb's config file")
	credsPath := flag.String("creds", "", "path to cobweb's credentials file (defaults next to --config)")
	printFirewall := flag.Bool("print-firewall", false, "print the nftables ruleset cobweb would apply for this config, then exit (changes nothing); try: cobweb --print-firewall | sudo nft -c -f -")
	flag.Parse()

	if *credsPath == "" {
		*credsPath = filepath.Join(filepath.Dir(*configPath), "credentials.json")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// A preview must never write anything - not the ruleset, and not even
	// the default config a fresh install would otherwise persist below -
	// so it runs before any of that.
	if *printFirewall {
		snap := cfg.Snapshot()
		ruleset, err := firewall.Render(snap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cobweb: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(ruleset)
		for _, w := range firewall.Warnings(snap) {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
		if !snap.FirewallEnabled {
			fmt.Fprintln(os.Stderr, "note: firewall_enabled is false in this config, so cobweb won't apply this on its own yet.")
		}
		return
	}

	// Persist immediately so a fresh install writes out its defaults to
	// disk right away, rather than only on the first settings change.
	if err := cfg.Save(); err != nil {
		log.Fatalf("failed to write initial config to %s: %v", *configPath, err)
	}
	log.Printf("cobweb: config loaded from %s", *configPath)

	credStore, err := auth.Load(*credsPath)
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}
	log.Printf("cobweb: credentials loaded from %s (user=%s)", *credsPath, credStore.Username())

	// DHCP and DNS both run under runForever: a bind failure (e.g. a
	// misconfigured interface name saved from the settings page) logs
	// the error and retries on a timer instead of taking down the
	// whole process. The dashboard itself has to stay reachable no
	// matter what these two are doing, since it's also how a person
	// would go fix a bad interface name in the first place.
	//
	// One DHCP listener runs per configured LAN segment (each VLAN
	// gets its own, bound to its own interface) - only DNS stays a
	// single shared listener, since one resolver can already answer
	// queries from every segment (see the design note in dnsserver's
	// package doc).
	startupSnap := cfg.Snapshot()
	for _, seg := range startupSnap.LANSegments {
		if seg.DHCPDisabled {
			log.Printf("dhcp[%s]: DHCP disabled for this segment, not starting a listener", seg.Name)
			continue
		}
		seg := seg // capture for the closure
		dhcpSrv := dhcp.New(cfg, seg.ID)
		go runForever("dhcp["+seg.Name+"]", dhcpSrv.Run)
	}

	dnsSrv := dnsserver.New(cfg)
	go runForever("dns", dnsSrv.Run)

	if startupSnap.SQMEnabled {
		if err := sqm.Apply(sqm.Config{
			Enabled:      true,
			WANInterface: startupSnap.WANInterface,
			DownloadMbit: startupSnap.SQMDownloadMbit,
			UploadMbit:   startupSnap.SQMUploadMbit,
		}); err != nil {
			log.Printf("sqm: failed to apply traffic shaping at startup: %v", err)
		}
	}

	// Like SQM, only touch the kernel if the person turned this on. A
	// failure here is logged, not fatal: the dashboard has to stay up so
	// the rules can be fixed from it.
	if startupSnap.FirewallEnabled {
		if err := firewall.Apply(startupSnap); err != nil {
			log.Printf("firewall: failed to apply rules at startup: %v", err)
		} else {
			log.Printf("firewall: applied %d port rule(s)", len(startupSnap.PortRules))
		}
	}

	webSrv, err := web.New(cfg, credStore)
	if err != nil {
		log.Fatalf("failed to initialize web server: %v", err)
	}

	segNames := make([]string, len(startupSnap.LANSegments))
	for i, seg := range startupSnap.LANSegments {
		segNames[i] = seg.Name + "(" + seg.Interface + ")"
	}
	log.Printf("cobweb: dashboard listening on %s (wan=%s segments=%v)", startupSnap.ListenAddr, startupSnap.WANInterface, segNames)
	log.Fatal(http.ListenAndServe(startupSnap.ListenAddr, webSrv.Routes()))
}

// runForever calls fn repeatedly, logging and backing off between
// attempts whenever it returns an error, so a bind failure in one
// subsystem never crashes the whole binary.
func runForever(name string, fn func() error) {
	backoff := 10 * time.Second
	for {
		err := fn()
		log.Printf("%s: stopped: %v (retrying in %s)", name, err, backoff)
		time.Sleep(backoff)
	}
}
