//go:build !linux

package dnsserver

import "net"

// Without IP_PKTINFO support the reply's source address is left to the OS.

func enablePktinfo(*net.UDPConn) error { return errNoPktinfo }

type pktinfoError string

func (e pktinfoError) Error() string { return string(e) }

const errNoPktinfo = pktinfoError("reply-source pinning is only supported on Linux")

func readQuery(c *net.UDPConn, buf []byte) (int, *net.UDPAddr, net.IP, error) {
	n, from, err := c.ReadFromUDP(buf)
	return n, from, nil, err
}

func writeReply(c *net.UDPConn, resp []byte, to *net.UDPAddr, _ net.IP) { c.WriteToUDP(resp, to) }
