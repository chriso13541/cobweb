package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
)

// MessageType is the DHCP message type (option 53).
type MessageType byte

const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	ACK      MessageType = 5
	NAK      MessageType = 6
	Release  MessageType = 7
	Inform   MessageType = 8
)

// Option codes we care about. Full list is much longer; these are the
// ones needed to run a functional home-network DHCP server.
const (
	optSubnetMask   = 1
	optRouter       = 3
	optDNSServer    = 6
	optHostname     = 12
	optRequestedIP  = 50
	optLeaseTime    = 51
	optMessageType  = 53
	optServerID     = 54
	optParamReqList = 55
	optEnd          = 255
)

var magicCookie = [4]byte{99, 130, 83, 99}

// Packet is a parsed DHCP message. Only the fields this server actually
// uses are broken out; everything else in the fixed header is kept
// implicit (e.g. secs, flags are read but not acted on).
type Packet struct {
	Op     byte // 1 = BOOTREQUEST, 2 = BOOTREPLY
	HType  byte
	HLen   byte
	XID    [4]byte
	Secs   uint16
	Flags  uint16
	CIAddr net.IP
	YIAddr net.IP
	SIAddr net.IP
	GIAddr net.IP
	CHAddr net.HardwareAddr

	MessageType MessageType
	RequestedIP net.IP // option 50, set on DISCOVER/REQUEST
	Hostname    string // option 12, client-supplied hostname
	ServerID    net.IP // option 54
}

// ParsePacket decodes a raw DHCP packet from the wire.
func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < 240 {
		return nil, errors.New("dhcp: packet too short")
	}

	p := &Packet{
		Op:     b[0],
		HType:  b[1],
		HLen:   b[2],
		Secs:   binary.BigEndian.Uint16(b[8:10]),
		Flags:  binary.BigEndian.Uint16(b[10:12]),
		CIAddr: net.IP(b[12:16]),
		YIAddr: net.IP(b[16:20]),
		SIAddr: net.IP(b[20:24]),
		GIAddr: net.IP(b[24:28]),
	}
	copy(p.XID[:], b[4:8])

	hlen := int(p.HLen)
	if hlen > 16 {
		hlen = 16
	}
	p.CHAddr = net.HardwareAddr(b[28 : 28+hlen])

	if b[236] != magicCookie[0] || b[237] != magicCookie[1] || b[238] != magicCookie[2] || b[239] != magicCookie[3] {
		return nil, errors.New("dhcp: bad magic cookie")
	}

	// Walk options starting at offset 240.
	i := 240
	for i < len(b) {
		code := b[i]
		if code == optEnd {
			break
		}
		if code == 0 { // pad
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		length := int(b[i+1])
		if i+2+length > len(b) {
			break
		}
		val := b[i+2 : i+2+length]

		switch code {
		case optMessageType:
			if length == 1 {
				p.MessageType = MessageType(val[0])
			}
		case optRequestedIP:
			if length == 4 {
				p.RequestedIP = net.IP(val)
			}
		case optHostname:
			p.Hostname = string(val)
		case optServerID:
			if length == 4 {
				p.ServerID = net.IP(val)
			}
		}

		i += 2 + length
	}

	return p, nil
}

// ReplyOpts carries everything the server needs to build an OFFER/ACK
// response for a given request.
type ReplyOpts struct {
	MessageType MessageType
	YourIP      net.IP
	ServerID    net.IP // this server's own LAN IP
	SubnetMask  net.IP
	Router      net.IP
	DNSServer   net.IP
	LeaseTime   uint32
}

// BuildReply constructs a BOOTREPLY packet in response to req, per the
// given ReplyOpts. XID and CHAddr are copied from the original request
// as required by the protocol so the client can match the reply to its
// outstanding transaction.
func BuildReply(req *Packet, opts ReplyOpts) []byte {
	buf := make([]byte, 240)

	buf[0] = 2 // BOOTREPLY
	buf[1] = req.HType
	buf[2] = req.HLen
	buf[3] = 0 // hops
	copy(buf[4:8], req.XID[:])
	// secs/flags left zero
	// ciaddr left zero (client doesn't have one yet)
	copy(buf[16:20], opts.YourIP.To4())
	copy(buf[20:24], opts.ServerID.To4())
	// giaddr left zero (no relay agent in a home network)
	copy(buf[28:28+len(req.CHAddr)], req.CHAddr)
	copy(buf[236:240], magicCookie[:])

	appendOpt := func(code byte, val []byte) {
		buf = append(buf, code, byte(len(val)))
		buf = append(buf, val...)
	}

	appendOpt(optMessageType, []byte{byte(opts.MessageType)})
	appendOpt(optServerID, opts.ServerID.To4())
	if opts.SubnetMask != nil {
		appendOpt(optSubnetMask, opts.SubnetMask.To4())
	}
	if opts.Router != nil {
		appendOpt(optRouter, opts.Router.To4())
	}
	if opts.DNSServer != nil {
		appendOpt(optDNSServer, opts.DNSServer.To4())
	}
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, opts.LeaseTime)
	appendOpt(optLeaseTime, leaseBytes)

	buf = append(buf, optEnd)

	return buf
}
