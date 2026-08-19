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
  "lan_segments": [
    {
      "id": "seg-a1b2c3d4e5f6",
      "name": "Trusted",
      "interface": "enp1s0",
      "address": "192.168.2.1",
      "subnet_mask": "255.255.255.0",
      "pool_start": "192.168.2.10",
      "pool_end": "192.168.2.254",
      "domain": "lan"
    },
    {
      "id": "seg-f6e5d4c3b2a1",
      "name": "IoT",
      "interface": "enp1s0.20",
      "address": "192.168.20.1",
      "subnet_mask": "255.255.255.0",
      "pool_start": "192.168.20.10",
      "pool_end": "192.168.20.254",
      "domain": "iot.lan"
    }
  ],
  "lease_seconds": 86400,
  "dns_mode": "forward",
  "upstream_servers": ["1.1.1.1:53", "9.9.9.9:53"],
  "listen_addr": "0.0.0.0:8070",
  "reservations": [
    {"mac": "08:62:66:a1:25:44", "ip": "192.168.2.10", "hostname": "stronghold", "segment_id": "seg-a1b2c3d4e5f6"}
  ],
  "dns_records": [
    {"name": "nas.lan", "ip": "192.168.2.10"}
  ],
  "leases": []
}
```

Each `id` is generated once and never changes, even if you rename a
segment or change its interface/pool later - reservations and leases
reference it, not the name, so renaming a segment never orphans
anything. An older single-LAN config (from before this shape existed)
is migrated into a one-segment list automatically the first time it's
loaded; nothing needs to be re-entered.

`leases` is maintained automatically by the DHCP server — dynamic
clients show up here as they get addresses, and it's what survives a
restart so devices don't lose their addresses just because cobweb
restarted.

## VLANs / multiple LAN segments

cobweb runs one DHCP listener per configured LAN segment, each bound
to its own interface. DNS stays a single shared resolver regardless of
how many segments exist - one UDP socket on `0.0.0.0:53` already
answers queries from every segment correctly, since replies route back
out whichever interface the kernel's own routing table says matches
the destination.

Getting an actual VLAN trunk working is three separate layers, and
cobweb only owns the last one:

**1. Switch side** — configure the port facing `cobweb` as a trunk
carrying whichever VLAN IDs you want routed (e.g. VLAN 10 and 20),
and configure your other switch ports as access ports on the
appropriate VLAN. This is switch-specific; consult its own
documentation.

**2. OS side** — create an 802.1q subinterface per VLAN with netplan:

```yaml
# /etc/netplan/02-vlans.yaml
network:
  version: 2
  vlans:
    enp1s0.20:
      id: 20
      link: enp1s0
      addresses: [192.168.20.1/24]
```

```bash
sudo netplan apply
ip link show enp1s0.20   # confirm it came up
```

Repeat per VLAN. The base interface (`enp1s0` here) stays as your
existing "Trusted" segment; each VLAN gets its own `enp1s0.<id>`
subinterface.

**3. nftables side** — since VLANs are "fully routed" by default (no
isolation between them, just forwarding + WAN masquerade), the
existing ruleset barely changes: `forward` just needs to accept
traffic between *any* LAN-tagged interface, not only the one it
already knew about:

```
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname { "enp1s0", "enp1s0.20" } oifname $WAN_IF accept
        iifname { "enp1s0", "enp1s0.20" } oifname { "enp1s0", "enp1s0.20" } accept
    }
}
```

Add every VLAN interface to both `{ }` sets as you create more
segments. If you want isolation between specific segments later
instead of full routing, that's a different (currently manual) ruleset
- ask if you want that built into the dashboard instead of hand-edited.

**4. cobweb side** — add the segment via Settings → LAN segments
(Name, Interface, Address, Subnet, Pool, Domain), then restart cobweb.
Adding/removing a segment through the dashboard updates the config
immediately, but the DHCP listener goroutines are only started at
boot - a restart is what actually brings a new segment's listener up
or tears a removed one down.

## Traffic shaping (Smart Queue Management)

Settings → Traffic shaping applies `cake` (fair queuing + active queue
management) to the WAN link, to fight bufferbloat - the reason a big
download can spike ping in a game running at the same time, even
though nothing is actually short on bandwidth. Applies immediately, no
restart needed.

This needs the `cake` and `ifb` kernel modules, both standard on a
normal Linux install:
```bash
sudo modprobe sch_cake
sudo modprobe ifb
```
If applying fails, the Settings page shows the real underlying error
directly rather than silently pretending it worked - the setting is
still saved either way, so retrying is just a matter of saving the
form again once the actual issue (usually a missing kernel module) is
fixed.

Set both the download and upload numbers to roughly 90% of your
*actual measured* throughput, not your ISP's advertised speed - if the
numbers are too high, packets still queue up further upstream (your
modem, your ISP) before cobweb ever sees them, and shaping can't do
its job; too low just wastes bandwidth you actually have.

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
