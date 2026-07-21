# cobweb

A self-contained home-router control plane: DHCP server, DNS server, and
a web dashboard, all in one Go binary with zero external dependencies.

It exists to replace the usual pile of separate config files
(`dnsmasq.conf`, systemd unit overrides, hand-edited lease files) with
one JSON config file that cobweb owns, and a dashboard where every
setting can actually be changed without SSHing in and editing text
files across three different applications.

## What it does

- **DHCP server** — DISCOVER/OFFER/REQUEST/ACK, a dynamic address pool,
  and static MAC → IP reservations. Implemented directly against the
  RFC 2131 wire format, no dnsmasq/isc-dhcp-server involved.
- **DNS server** — answers local names (both manually defined records
  and every current DHCP lease's hostname, automatically, under a
  configurable local domain like `.lan`) and transparently forwards
  everything else to upstream resolvers (Cloudflare/Quad9 by default).
- **Web dashboard** — live device list (htmx-polled, no page reloads),
  WAN/LAN interface status, and a settings page for reservations, DNS
  records, and core network config — all writing straight to the one
  config file.

## What it does *not* do

cobweb doesn't touch NAT/firewalling — that stays as `nftables` (or
`pf` on BSD), configured separately at the OS level, since packet
filtering is a kernel-level concern that doesn't benefit from being
reimplemented in userspace. cobweb's job is address assignment and name
resolution, not routing policy.

## Requirements

- Go 1.22+ (only for building — the resulting binary has zero runtime
  dependencies)
- Linux, run as root (or with `CAP_NET_BIND_SERVICE`), since DHCP/DNS
  bind privileged ports (67, 53)
- `nftables` (or equivalent) already configured for NAT/masquerade on
  your WAN interface — cobweb assumes this is already in place

## Build & run

```bash
git clone <this-repo> cobweb
cd cobweb
go build -o cobweb ./cmd/cobweb
sudo ./cobweb --config /etc/cobweb/config.json
```

That's the whole install. No `go get`, no package manager, no internet
access required at build time — everything is standard library.

On first run, cobweb writes out a default config to the path you give
it (creating the directory if needed) and starts serving immediately.
Open `http://<this-box's-LAN-facing-IP>:8070/` from any device on your
home network to reach the dashboard, and `/settings` to configure
interfaces, the DHCP pool, reservations, and DNS.

## Running as a service

```ini
# /etc/systemd/system/cobweb.service
[Unit]
Description=cobweb router control plane
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/cobweb --config /etc/cobweb/config.json
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp cobweb /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now cobweb
```

## Config file

Everything lives in one JSON file (default `/etc/cobweb/config.json`).
You generally shouldn't need to hand-edit it — the dashboard's
`/settings` page covers all of it — but the shape is:

```json
{
  "wan_interface": "wlp2s0",
  "lan_interface": "enp1s0",
  "lan_address": "192.168.2.1",
  "subnet_mask": "255.255.255.0",
  "pool_start": "192.168.2.10",
  "pool_end": "192.168.2.254",
  "lease_seconds": 86400,
  "domain": "lan",
  "upstream_servers": ["1.1.1.1:53", "9.9.9.9:53"],
  "listen_addr": "0.0.0.0:8070",
  "reservations": [
    {"mac": "08:62:66:a1:25:44", "ip": "192.168.2.10", "hostname": "stronghold"}
  ],
  "dns_records": [
    {"name": "nas.lan", "ip": "192.168.2.10"}
  ],
  "leases": []
}
```

`leases` is maintained automatically by the DHCP server — dynamic
clients show up here as they get addresses, and it's what survives a
restart so devices don't lose their addresses just because cobweb
restarted.

## Project layout

```
cmd/cobweb/          entry point - loads config, starts all three servers
internal/config/      shared JSON-backed config, thread-safe
internal/dhcp/        DHCPv4 packet parsing + server state machine
internal/dnsserver/   DNS local-record resolution + upstream forwarding
internal/netstat/     interface link state / traffic counters via /sys
internal/web/         dashboard HTTP handlers + htmx templates
```

## License

Personal project, use it however you like.
