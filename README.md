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

Unit/init files for both are in `init/` and are meant to be installed
as-is, not copy-pasted by hand.

### systemd

```bash
sudo cp cobweb /usr/local/bin/
sudo mkdir -p /etc/cobweb
sudo cp init/systemd/cobweb.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cobweb
```

Check it with `systemctl status cobweb` and `journalctl -u cobweb -f`.

If `systemctl start`/`enable --now` seems to hang: it's ordered after
`network.target` (basically instant), not `network-online.target`,
specifically because the latter pulls in a wait-online helper that can
hang or time out slowly on multi-interface boxes (e.g. a WiFi WAN
client alongside a wired LAN link, as on this project's own reference
setup). If you're still seeing a hang, it's not cobweb's unit file -
check `systemctl status network-online.target` and
`journalctl -u NetworkManager-wait-online.service` (or
`systemd-networkd-wait-online.service`) for the real cause.

### OpenRC

```bash
sudo cp cobweb /usr/local/bin/
sudo mkdir -p /etc/cobweb
sudo cp init/openrc/cobweb.openrc /etc/init.d/cobweb
sudo chmod +x /etc/init.d/cobweb
sudo rc-update add cobweb default
sudo rc-service cobweb start
```

Logs go to `/var/log/cobweb.log`; check status with `rc-service cobweb status`.

### Both

Either way, on first launch cobweb writes its default `config.json`
and `credentials.json` (default login `admin`/`admin` - change it
immediately from Settings → Account) to `/etc/cobweb/`, and keeps
running under whichever init system restarts it if it ever exits.

### Running without full root

Both unit files run cobweb as root by default, since it binds
privileged ports (53, 67) and uses `SO_BINDTODEVICE` (which needs
`CAP_NET_RAW`). If you'd rather not run it as full root, the systemd
unit can be adjusted to run as a dedicated user with just the specific
capabilities it needs:

```ini
User=cobweb
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
```

This needs a `cobweb` system user created ahead of time, and
`/etc/cobweb` owned by that user (`chown -R cobweb:cobweb /etc/cobweb`)
so it can still write its config and credential files. Not set up by
default because it's an extra failure mode to debug (permission
errors on the config directory) for a single-purpose home gateway box
where root is already the trust boundary - worth doing if you want the
extra hardening, not required.

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
cmd/cobweb/          entry point - loads config, starts all servers with crash-resilient retry
internal/auth/        login: PBKDF2 password hashing, sessions, brute-force throttling
internal/config/      shared JSON-backed config, thread-safe
internal/dhcp/        DHCPv4 packet parsing + server state machine
internal/dnsserver/   local records, forward mode, and the recursive resolver (root/TLD/authoritative)
internal/netstat/     interface link state / traffic counters via /sys
internal/status/      DHCP/DNS live health, surfaced on the dashboard
internal/web/         dashboard HTTP handlers + htmx templates
init/systemd/         systemd unit file
init/openrc/          OpenRC init script
```

## License

Personal project, use it however you like.
