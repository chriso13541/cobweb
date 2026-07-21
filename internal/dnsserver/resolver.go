package dnsserver

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	typeNS    = 2
	typeCNAME = 5

	maxReferralHops = 20
	queryTimeout    = 3 * time.Second
)

// rr is one parsed resource record from a DNS message. RDataOffset is
// the absolute byte offset within the original message where RDATA
// begins - needed because RDATA for types like NS/CNAME can itself
// contain a compression pointer, which can only be resolved against
// the full original buffer.
type rr struct {
	Name        string
	Type        uint16
	Class       uint16
	TTL         uint32
	RData       []byte
	RDataOffset int
}

// dnsMessage is a fully parsed DNS message: header, question, and all
// three resource record sections. Raw is kept around so RDATA name
// pointers (NS/CNAME targets) can be decompressed on demand.
type dnsMessage struct {
	ID         uint16
	Flags      uint16
	QName      string
	QType      uint16
	QClass     uint16
	Answers    []rr
	Authority  []rr
	Additional []rr
	Raw        []byte
}

// readNameCompressed decodes a DNS wire-format name starting at
// offset, following compression pointers (RFC 1035 §4.1.4) as needed.
// next is the offset immediately after the name *as it appeared in the
// original stream* - i.e. right after a pointer if one was followed,
// not after wherever the pointer led.
func readNameCompressed(msg []byte, offset int) (name string, next int, err error) {
	var labels []string
	pos := offset
	jumped := false
	jumps := 0

	for {
		if pos >= len(msg) {
			return "", 0, fmt.Errorf("dns: name read out of bounds")
		}
		length := int(msg[pos])

		if length == 0 {
			pos++
			break
		}

		if length&0xC0 == 0xC0 { // top two bits set: compression pointer
			if pos+1 >= len(msg) {
				return "", 0, fmt.Errorf("dns: truncated pointer")
			}
			ptr := (length&0x3F)<<8 | int(msg[pos+1])
			if !jumped {
				next = pos + 2
			}
			jumps++
			if jumps > maxReferralHops {
				return "", 0, fmt.Errorf("dns: too many compression pointer jumps")
			}
			pos = ptr
			jumped = true
			continue
		}

		pos++
		if pos+length > len(msg) {
			return "", 0, fmt.Errorf("dns: label out of bounds")
		}
		labels = append(labels, string(msg[pos:pos+length]))
		pos += length
	}

	if !jumped {
		next = pos
	}
	return strings.Join(labels, "."), next, nil
}

// readRR parses one resource record starting at offset.
func readRR(msg []byte, offset int) (record rr, next int, err error) {
	name, offset, err := readNameCompressed(msg, offset)
	if err != nil {
		return rr{}, 0, err
	}
	if offset+10 > len(msg) {
		return rr{}, 0, fmt.Errorf("dns: rr header out of bounds")
	}
	typ := binary.BigEndian.Uint16(msg[offset : offset+2])
	class := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
	ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
	rdlen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
	offset += 10
	if offset+rdlen > len(msg) {
		return rr{}, 0, fmt.Errorf("dns: rdata out of bounds")
	}
	record = rr{
		Name:        name,
		Type:        typ,
		Class:       class,
		TTL:         ttl,
		RData:       msg[offset : offset+rdlen],
		RDataOffset: offset,
	}
	return record, offset + rdlen, nil
}

// parseFullMessage parses header, question, and all RR sections. Used
// for interpreting responses from root/TLD/authoritative servers,
// which is a strictly larger job than parseQuestion (used elsewhere
// for incoming client queries).
func parseFullMessage(msg []byte) (*dnsMessage, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: message too short")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))

	offset := 12
	var qName string
	var qType, qClass uint16
	for i := 0; i < qdCount; i++ {
		name, next, err := readNameCompressed(msg, offset)
		if err != nil {
			return nil, err
		}
		if next+4 > len(msg) {
			return nil, fmt.Errorf("dns: truncated question")
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		class := binary.BigEndian.Uint16(msg[next+2 : next+4])
		offset = next + 4
		if i == 0 {
			qName, qType, qClass = name, typ, class
		}
	}

	readSection := func(count int) ([]rr, error) {
		var out []rr
		for i := 0; i < count; i++ {
			record, next, err := readRR(msg, offset)
			if err != nil {
				return nil, err
			}
			out = append(out, record)
			offset = next
		}
		return out, nil
	}

	answers, err := readSection(anCount)
	if err != nil {
		return nil, err
	}
	authority, err := readSection(nsCount)
	if err != nil {
		return nil, err
	}
	additional, err := readSection(arCount)
	if err != nil {
		return nil, err
	}

	return &dnsMessage{
		ID: id, Flags: flags,
		QName: qName, QType: qType, QClass: qClass,
		Answers: answers, Authority: authority, Additional: additional,
		Raw: msg,
	}, nil
}

// buildIterativeQuery constructs a non-recursive query (RD=0) - the
// resolver walks the referral chain itself rather than asking the
// remote server to recurse on its behalf, which is what makes this a
// real recursive *resolver* rather than just another forwarder.
func buildIterativeQuery(id uint16, qname string, qtype uint16) []byte {
	buf := make([]byte, 0, 32)
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x00, 0x00) // all flags zero: QR=0, RD=0
	buf = append(buf, 0, 1)       // QDCOUNT=1
	buf = append(buf, 0, 0, 0, 0, 0, 0)

	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // root label
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0, qClassIN)
	return buf
}

// queryServers tries each address in servers (each already a full
// "host:port" address) in turn, short timeout each, until one answers,
// returning the first successfully parsed response.
func queryServers(servers []string, qname string, qtype uint16) (*dnsMessage, error) {
	id := uint16(rand.Intn(65536))
	query := buildIterativeQuery(id, qname, qtype)

	var lastErr error
	for _, srv := range servers {
		conn, err := net.DialTimeout("udp", srv, queryTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		conn.SetDeadline(time.Now().Add(queryTimeout))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		msg, err := parseFullMessage(buf[:n])
		if err != nil {
			lastErr = err
			continue
		}
		if msg.ID != id {
			lastErr = fmt.Errorf("dns: response id mismatch")
			continue
		}
		return msg, nil
	}
	return nil, fmt.Errorf("dns: all servers unreachable: %w", lastErr)
}

// resolvedAnswer is the result of a successful iterative resolution.
type resolvedAnswer struct {
	IPs []net.IP
	TTL uint32
}

// resolveIterative walks the DNS delegation chain by hand: start at
// the root servers, follow NS referrals down through the TLD and
// authoritative servers, until an answer (or a CNAME chain leading to
// one) is found. This is what makes queries private in the sense that
// matters here - no single upstream server ever sees the full name
// being resolved end-to-end; each server in the chain only sees the
// portion relevant to its own zone.
func resolveIterative(qname string, qtype uint16) (*resolvedAnswer, error) {
	addrs := make([]string, len(rootServers))
	for i, ip := range rootServers {
		addrs[i] = net.JoinHostPort(ip, "53")
	}
	return resolveIterativeFrom(addrs, qname, qtype)
}

// resolveIterativeFrom is the actual implementation, parameterized on
// the starting server list so tests can exercise the full referral
// walk against local fake servers rather than the real DNS root.
func resolveIterativeFrom(startServers []string, qname string, qtype uint16) (*resolvedAnswer, error) {
	currentName := strings.ToLower(strings.TrimSuffix(qname, ".")) + "."
	servers := append([]string{}, startServers...)

	for hop := 0; hop < maxReferralHops; hop++ {
		resp, err := queryServers(servers, currentName, qtype)
		if err != nil {
			return nil, err
		}

		var ips []net.IP
		var cnameTarget string
		minTTL := ^uint32(0)

		for _, a := range resp.Answers {
			if !strings.EqualFold(strings.TrimSuffix(a.Name, "."), strings.TrimSuffix(currentName, ".")) {
				continue
			}
			switch a.Type {
			case qTypeA:
				if len(a.RData) == 4 {
					ips = append(ips, net.IP(a.RData))
					if a.TTL < minTTL {
						minTTL = a.TTL
					}
				}
			case typeCNAME:
				target, _, err := readNameCompressed(resp.Raw, a.RDataOffset)
				if err == nil {
					cnameTarget = target
					if a.TTL < minTTL {
						minTTL = a.TTL
					}
				}
			}
		}

		if len(ips) > 0 {
			if minTTL == ^uint32(0) {
				minTTL = 60
			}
			return &resolvedAnswer{IPs: ips, TTL: minTTL}, nil
		}

		if cnameTarget != "" {
			currentName = strings.ToLower(strings.TrimSuffix(cnameTarget, ".")) + "."
			servers = append([]string{}, startServers...) // restart from root for the new name
			continue
		}

		// No direct answer: look for a referral to more specific
		// servers in the authority section, resolved via glue (A)
		// records in the additional section.
		nsNames := map[string]bool{}
		for _, a := range resp.Authority {
			if a.Type == typeNS {
				name, _, err := readNameCompressed(resp.Raw, a.RDataOffset)
				if err == nil {
					nsNames[strings.ToLower(name)] = true
				}
			}
		}
		if len(nsNames) == 0 {
			return nil, fmt.Errorf("dns: no answer or referral for %s", currentName)
		}

		var nextServers []string
		for _, a := range resp.Additional {
			if a.Type == qTypeA && len(a.RData) == 4 && nsNames[strings.ToLower(strings.TrimSuffix(a.Name, "."))] {
				nextServers = append(nextServers, net.JoinHostPort(net.IP(a.RData).String(), "53"))
			}
		}
		if len(nextServers) == 0 {
			return nil, fmt.Errorf("dns: referral without glue records for %s", currentName)
		}
		servers = nextServers
	}

	return nil, fmt.Errorf("dns: too many referral hops resolving %s", qname)
}
