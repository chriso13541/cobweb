//go:build linux

package dnsserver

import (
	"net"
	"syscall"
	"unsafe"
)

// A DNS server listening on 0.0.0.0 has to answer from the address the
// client asked, or the client drops the reply: UDP clients ignore a response
// whose source differs from the destination they sent to. Left alone, Linux
// picks the source from the outgoing interface, so a VPN client asking
// 192.168.2.1 would hear back from 10.8.0.1 and every lookup would time out.
// IP_PKTINFO tells us which local address each query arrived on, and lets us
// pin the reply's source to it.

const pktinfoLen = 12 // struct in_pktinfo: int ifindex; in_addr spec_dst; in_addr addr

// enablePktinfo asks the kernel to report each datagram's destination address.
func enablePktinfo(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	}); err != nil {
		return err
	}
	return serr
}

// readQuery reads one datagram and the local address it was sent to (nil if
// the kernel didn't say).
func readQuery(c *net.UDPConn, buf []byte) (n int, from *net.UDPAddr, local net.IP, err error) {
	oob := make([]byte, 128)
	n, oobn, _, from, err := c.ReadMsgUDP(buf, oob)
	if err != nil {
		return 0, nil, nil, err
	}
	return n, from, localFromOOB(oob[:oobn]), nil
}

func localFromOOB(oob []byte) net.IP {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= pktinfoLen {
			ip := net.IPv4(m.Data[8], m.Data[9], m.Data[10], m.Data[11])
			if !ip.IsUnspecified() {
				return ip
			}
		}
	}
	return nil
}

// writeReply sends resp to the client, from local when it is known.
func writeReply(c *net.UDPConn, resp []byte, to *net.UDPAddr, local net.IP) {
	ip4 := local.To4()
	if ip4 == nil {
		c.WriteToUDP(resp, to)
		return
	}
	c.WriteMsgUDP(resp, replyOOB(ip4), to)
}

// replyOOB builds the IP_PKTINFO control message that sets the reply's source
// address (ipi_spec_dst) and leaves the interface to the routing table.
func replyOOB(ip4 net.IP) []byte {
	b := make([]byte, syscall.CmsgSpace(pktinfoLen))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = syscall.IPPROTO_IP
	h.Type = syscall.IP_PKTINFO
	h.SetLen(syscall.CmsgLen(pktinfoLen))
	copy(b[syscall.CmsgLen(0)+4:], ip4) // after the 4-byte ifindex, which stays 0
	return b
}
