package dnsserver

// rootServers is the current IANA root hints list (IPv4 addresses of
// the 13 root name servers). This is the standard starting point for
// recursive DNS resolution - every resolver on the internet begins
// here. Source: https://www.iana.org/domains/root/servers - if this
// ever needs updating, that page is the authoritative reference.
var rootServers = []string{
	"198.41.0.4",     // a.root-servers.net
	"199.9.14.201",   // b.root-servers.net
	"192.33.4.12",    // c.root-servers.net
	"199.7.91.13",    // d.root-servers.net
	"192.203.230.10", // e.root-servers.net
	"192.5.5.241",    // f.root-servers.net
	"192.112.36.4",   // g.root-servers.net
	"198.97.190.53",  // h.root-servers.net
	"192.36.148.17",  // i.root-servers.net
	"192.58.128.30",  // j.root-servers.net
	"193.0.14.129",   // k.root-servers.net
	"199.7.83.42",    // l.root-servers.net
	"202.12.27.33",   // m.root-servers.net
}
