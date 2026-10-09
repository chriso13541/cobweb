//go:build linux

package dnsserver

import (
	"net"
	"testing"
	"time"
)

// A reply must come from the address the query was sent to. 127.0.0.2 is a
// local address on Linux, so a client can ask it and (without the fix) hear
// back from 127.0.0.1 - which a connected UDP socket, like a real resolver,
// silently discards.
func TestReplyComesFromTheAddressAsked(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Skipf("can't listen: %v", err)
	}
	defer srv.Close()
	if err := enablePktinfo(srv); err != nil {
		t.Fatalf("enablePktinfo: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, local, err := readQuery(srv, buf)
			if err != nil {
				return
			}
			writeReply(srv, append([]byte("re:"), buf[:n]...), from, local)
		}
	}()
	port := srv.LocalAddr().(*net.UDPAddr).Port

	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "127.1.2.3"} {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		c.Close()
		if err != nil || string(buf[:n]) != "re:hello" {
			t.Errorf("asking %s: got %q, %v - the reply was probably sent from a different address", ip, buf[:n], err)
		}
	}
}

func TestLocalFromOOBIgnoresGarbage(t *testing.T) {
	for _, oob := range [][]byte{nil, {}, {1, 2, 3}, make([]byte, 64)} {
		if ip := localFromOOB(oob); ip != nil {
			t.Errorf("localFromOOB(%v) = %v, want nil", oob, ip)
		}
	}
}
