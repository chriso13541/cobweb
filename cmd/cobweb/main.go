// Command cobweb is a self-contained home-router control plane: a
// DHCP server, a DNS server, and a web dashboard, all driven by one
// JSON config file. There is no dependency on dnsmasq or any other
// external daemon - everything network-facing that cobweb does, it
// does itself, and every setting is editable from the dashboard rather
// than by hand-editing config files scattered across the system.
package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"cobweb/internal/auth"
	"cobweb/internal/config"
	"cobweb/internal/dhcp"
	"cobweb/internal/dnsserver"
	"cobweb/internal/web"
)

func main() {
	configPath := flag.String("config", "/etc/cobweb/config.json", "path to cobweb's config file")
	credsPath := flag.String("creds", "", "path to cobweb's credentials file (defaults next to --config)")
	flag.Parse()

	if *credsPath == "" {
		*credsPath = filepath.Join(filepath.Dir(*configPath), "credentials.json")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
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
	dhcpSrv := dhcp.New(cfg)
	go runForever("dhcp", dhcpSrv.Run)

	dnsSrv := dnsserver.New(cfg)
	go runForever("dns", dnsSrv.Run)

	webSrv, err := web.New(cfg, credStore)
	if err != nil {
		log.Fatalf("failed to initialize web server: %v", err)
	}

	snap := cfg.Snapshot()
	log.Printf("cobweb: dashboard listening on %s (wan=%s lan=%s)", snap.ListenAddr, snap.WANInterface, snap.LANInterface)
	log.Fatal(http.ListenAndServe(snap.ListenAddr, webSrv.Routes()))
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
