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

	"cobweb/internal/config"
	"cobweb/internal/dhcp"
	"cobweb/internal/dnsserver"
	"cobweb/internal/web"
)

func main() {
	configPath := flag.String("config", "/etc/cobweb/config.json", "path to cobweb's config file")
	flag.Parse()

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

	dhcpSrv := dhcp.New(cfg)
	go func() {
		if err := dhcpSrv.Run(); err != nil {
			log.Fatalf("dhcp server failed: %v", err)
		}
	}()

	dnsSrv := dnsserver.New(cfg)
	go func() {
		if err := dnsSrv.Run(); err != nil {
			log.Fatalf("dns server failed: %v", err)
		}
	}()

	webSrv, err := web.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialize web server: %v", err)
	}

	snap := cfg.Snapshot()
	log.Printf("cobweb: dashboard listening on %s (wan=%s lan=%s)", snap.ListenAddr, snap.WANInterface, snap.LANInterface)
	log.Fatal(http.ListenAndServe(snap.ListenAddr, webSrv.Routes()))
}
