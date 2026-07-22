package dnsserver

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeServer is a minimal UDP DNS stub for tests: it inspects the
// question name and returns a pre-built response, letting us simulate
// a real root -> TLD -> authoritative referral chain without touching
// the actual internet (which this sandbox can't reach anyway).
//
// Real glue records only ever carry an IP address (DNS always assumes
// port 53 for the next hop), so unlike a typical test double, these
// have to actually listen on :53 - just on distinct loopback addresses
// (127.0.0.2, 127.0.0.3, ...) so multiple fake servers can coexist.
func startFakeServer(t *testing.T, ip string, handler func(qname string, qtype uint16) []byte) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 53})
	if err != nil {
		t.Fatalf("failed to start fake server on %s:53: %v", ip, err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q, err := parseQuestion(buf[:n])
			if err != nil {
				continue
			}
			resp := handler(q.name, q.qtype)
			if resp == nil {
				continue
			}
			// Patch in the real query ID so queryServers' ID check passes.
			resp[0], resp[1] = buf[0], buf[1]
			conn.WriteToUDP(resp, addr)
		}
	}()

	return ip
}

// buildTestMessage assembles a raw DNS response by hand: header +
// echoed question + arbitrary answer/authority/additional sections
// (each given as already-encoded bytes), so tests can construct
// exactly the wire format a real server would send, including
// compression pointers.
func buildTestMessage(qname string, qtype uint16, answers, authority, additional []byte, anCount, nsCount, arCount int) []byte {
	buf := make([]byte, 2, 64)
	flags := uint16(flagQR)
	buf = append(buf, byte(flags>>8), byte(flags))
	buf = append(buf, 0, 1)
	buf = append(buf, byte(anCount>>8), byte(anCount))
	buf = append(buf, byte(nsCount>>8), byte(nsCount))
	buf = append(buf, byte(arCount>>8), byte(arCount))

	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0, qClassIN)

	buf = append(buf, answers...)
	buf = append(buf, authority...)
	buf = append(buf, additional...)
	return buf
}

// encodeName writes a plain (uncompressed) name in wire format.
func encodeName(name string) []byte {
	var buf []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	return buf
}

// encodeRR builds one resource record. nameBytes lets callers pass
// either a plain encoded name or a 2-byte compression pointer (0xC0,
// offset) to exercise the decompression path.
func encodeRR(nameBytes []byte, rtype uint16, ttl uint32, rdata []byte) []byte {
	buf := append([]byte{}, nameBytes...)
	buf = append(buf, byte(rtype>>8), byte(rtype))
	buf = append(buf, 0, qClassIN)
	buf = append(buf, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
	buf = append(buf, byte(len(rdata)>>8), byte(len(rdata)))
	buf = append(buf, rdata...)
	return buf
}

func TestReferralChainEndToEnd(t *testing.T) {
	const authIP = "127.0.0.4"
	const tldIP = "127.0.0.3"
	const rootIP = "127.0.0.2"

	// Authoritative server for example.com: answers directly with an A
	// record.
	startFakeServer(t, authIP, func(qname string, qtype uint16) []byte {
		if qname != "example.com" || qtype != qTypeA {
			return nil
		}
		answer := encodeRR(encodeName("example.com"), qTypeA, 300, net.IPv4(93, 184, 216, 34).To4())
		return buildTestMessage(qname, qtype, answer, nil, nil, 1, 0, 0)
	})

	// TLD server for .com: refers to the authoritative server, with a
	// glue A record so the resolver doesn't need a separate lookup.
	// The NS record's name uses a compression pointer back to the
	// question name (offset 12) to exercise decompression.
	startFakeServer(t, tldIP, func(qname string, qtype uint16) []byte {
		if qname != "example.com" {
			return nil
		}
		nsName := encodeName("ns1.example.com")
		authority := encodeRR([]byte{0xC0, 0x0C}, typeNS, 300, nsName)
		glue := encodeRR(encodeName("ns1.example.com"), qTypeA, 300, net.ParseIP(authIP).To4())
		return buildTestMessage(qname, qtype, nil, authority, glue, 0, 1, 1)
	})

	// "Root" server: refers to the TLD server the same way.
	startFakeServer(t, rootIP, func(qname string, qtype uint16) []byte {
		if qname != "example.com" {
			return nil
		}
		nsName := encodeName("a.gtld-servers.net")
		authority := encodeRR([]byte{0xC0, 0x0C}, typeNS, 300, nsName)
		glue := encodeRR(encodeName("a.gtld-servers.net"), qTypeA, 300, net.ParseIP(tldIP).To4())
		return buildTestMessage(qname, qtype, nil, authority, glue, 0, 1, 1)
	})

	answer, err := resolveIterativeFrom([]string{net.JoinHostPort(rootIP, "53")}, "example.com", qTypeA, maxResolutionDepth)
	if err != nil {
		t.Fatalf("resolveIterativeFrom failed: %v", err)
	}
	if len(answer.IPs) != 1 || !answer.IPs[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("got IPs %v, want [93.184.216.34]", answer.IPs)
	}
	if answer.TTL != 300 {
		t.Fatalf("got TTL %d, want 300", answer.TTL)
	}
}

func TestReferralWithoutGlueRecords(t *testing.T) {
	// This mirrors the real-world failure: a zone (e.g. anything on
	// Cloudflare or Azure Traffic Manager) delegates to a nameserver
	// hosted on a completely different domain, so the parent zone has
	// no reason to include glue for it. The resolver has to fall back
	// to resolving that nameserver's hostname on its own.
	const authIP = "127.0.0.7" // ns.otherprovider.net's real address
	const rootIP = "127.0.0.5" // stands in for both "root" and "TLD" here

	// authIP answers both roles needed: the actual answer for
	// mysite.example, and the A record for ns.otherprovider.net when
	// asked directly (simulating that name's own delegation chain
	// terminating immediately at this same server for test simplicity).
	startFakeServer(t, authIP, func(qname string, qtype uint16) []byte {
		switch qname {
		case "mysite.example":
			answer := encodeRR(encodeName("mysite.example"), qTypeA, 120, net.IPv4(203, 0, 113, 9).To4())
			return buildTestMessage(qname, qtype, answer, nil, nil, 1, 0, 0)
		case "ns.otherprovider.net":
			answer := encodeRR(encodeName("ns.otherprovider.net"), qTypeA, 120, net.ParseIP(authIP).To4())
			return buildTestMessage(qname, qtype, answer, nil, nil, 1, 0, 0)
		}
		return nil
	})

	// "Root": refers mysite.example to ns.otherprovider.net with NO
	// glue record at all - the exact condition that used to fail.
	startFakeServer(t, rootIP, func(qname string, qtype uint16) []byte {
		if qname == "mysite.example" {
			nsName := encodeName("ns.otherprovider.net")
			authority := encodeRR(encodeName("example"), typeNS, 300, nsName)
			return buildTestMessage(qname, qtype, nil, authority, nil, 0, 1, 0)
		}
		if qname == "ns.otherprovider.net" {
			// Root also needs to answer for the NS hostname itself,
			// referring straight to the authoritative server that
			// actually knows it (simulating a second delegation hop).
			nsName := encodeName("ns.otherprovider.net")
			authority := encodeRR(encodeName("otherprovider.net"), typeNS, 300, nsName)
			glue := encodeRR(encodeName("ns.otherprovider.net"), qTypeA, 300, net.ParseIP(authIP).To4())
			return buildTestMessage(qname, qtype, nil, authority, glue, 0, 1, 1)
		}
		return nil
	})

	answer, err := resolveIterativeFrom([]string{net.JoinHostPort(rootIP, "53")}, "mysite.example", qTypeA, maxResolutionDepth)
	if err != nil {
		t.Fatalf("resolveIterativeFrom failed on glueless referral: %v", err)
	}
	if len(answer.IPs) != 1 || !answer.IPs[0].Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatalf("got IPs %v, want [203.0.113.9]", answer.IPs)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	c := newRecursiveCache()
	ips := []net.IP{net.IPv4(1, 2, 3, 4)}
	c.set("example.com|A", ips, 5)

	got, ok := c.get("example.com|A")
	if !ok || !got[0].Equal(ips[0]) {
		t.Fatalf("expected cache hit with %v, got %v (ok=%v)", ips, got, ok)
	}

	// Force expiry and confirm it's gone.
	c.entries["example.com|A"] = cacheEntry{ips: ips, expiresAt: time.Now().Add(-time.Second)}
	if _, ok := c.get("example.com|A"); ok {
		t.Fatalf("expected cache miss after expiry")
	}
}

func TestNameDecompressionRoundTrip(t *testing.T) {
	// Build a message where a second name is a pointer back to the
	// first, and confirm both decode to the same string.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, encodeName("www.example.com")...)
	pointerOffset := len(msg)
	msg = append(msg, 0xC0, byte(12)) // pointer to offset 12

	name1, next1, err := readNameCompressed(msg, 12)
	if err != nil {
		t.Fatalf("readNameCompressed(first) failed: %v", err)
	}
	if name1 != "www.example.com" {
		t.Fatalf("got %q, want www.example.com", name1)
	}
	if next1 != pointerOffset {
		t.Fatalf("got next=%d, want %d", next1, pointerOffset)
	}

	name2, next2, err := readNameCompressed(msg, pointerOffset)
	if err != nil {
		t.Fatalf("readNameCompressed(pointer) failed: %v", err)
	}
	if name2 != "www.example.com" {
		t.Fatalf("got %q via pointer, want www.example.com", name2)
	}
	if next2 != pointerOffset+2 {
		t.Fatalf("got next=%d, want %d", next2, pointerOffset+2)
	}
}
