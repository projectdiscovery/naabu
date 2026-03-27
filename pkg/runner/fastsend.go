package runner

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/Mzack9999/gopacket/rawsend"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

// SYNSender builds and sends raw TCP SYN packets without gopacket
// serialization. Per-packet work: patch 3 fields + one sendto syscall.
//
// Sending is delegated to rawsend.Sender (direct sendto) with an
// optional rawsend.Batch for sendmmsg on Linux.
//
// NOT safe for concurrent use, reuses internal buffers.
type SYNSender struct {
	sender  *rawsend.Sender
	batch   *rawsend.Batch
	srcPort uint16
	baseSum uint32
	seq     uint32
	pkt     [24]byte
}

var (
	errNoRawConn    = errors.New("no raw IPv4 connection")
	errEthernetPath = errors.New("ethernet framing path requires standard sender")
	errNoSourceIP   = errors.New("cannot determine source IP")
)

func newSYNSender(handler *scan.ListenHandler) (*SYNSender, error) {
	if handler == nil || handler.TcpConn4 == nil {
		return nil, errNoRawConn
	}
	if handler.SourceIp4 != nil && handler.SourceHW != nil {
		return nil, errEthernetPath
	}

	var srcIP net.IP
	if handler.SourceIp4 != nil {
		srcIP = handler.SourceIp4
	} else if scan.PkgRouter != nil {
		_, _, srcIP, _ = scan.PkgRouter.Route(net.IPv4(1, 1, 1, 1))
	}
	if srcIP == nil {
		return nil, errNoSourceIP
	}
	src4 := srcIP.To4()
	if src4 == nil {
		return nil, errNoSourceIP
	}

	sender, err := rawsend.NewFromIPConn(handler.TcpConn4)
	if err != nil {
		return nil, err
	}

	s := &SYNSender{
		sender:  sender,
		batch:   rawsend.NewBatch(sender.FD(), 32, 24),
		srcPort: uint16(handler.Port),
	}

	binary.BigEndian.PutUint16(s.pkt[0:2], s.srcPort)
	s.pkt[12] = 0x60 // DataOffset: 6 words (24 bytes)
	s.pkt[13] = 0x02 // Flags: SYN
	binary.BigEndian.PutUint16(s.pkt[14:16], 1024)
	s.pkt[20] = 2 // MSS option kind
	s.pkt[21] = 4 // MSS option length
	binary.BigEndian.PutUint16(s.pkt[22:24], 1460)

	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src4[2:4]))
	sum += 6  // zero + protocol (TCP)
	sum += 24 // TCP segment length
	sum += uint32(s.srcPort)
	sum += 0x6002 // DataOff(0x60) | SYN(0x02)
	sum += 0x0400 // Window(1024)
	sum += 0x0204 // MSS kind(2) + len(4)
	sum += 0x05B4 // MSS value(1460)
	s.baseSum = sum

	return s, nil
}

func (s *SYNSender) send(dstIP [4]byte, dstPort uint16) error {
	s.seq++
	seq := s.seq

	binary.BigEndian.PutUint16(s.pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(s.pkt[4:8], seq)

	sum := s.baseSum +
		uint32(binary.BigEndian.Uint16(dstIP[0:2])) +
		uint32(binary.BigEndian.Uint16(dstIP[2:4])) +
		uint32(dstPort) +
		uint32(seq>>16) +
		uint32(seq&0xffff)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	binary.BigEndian.PutUint16(s.pkt[16:18], ^uint16(sum))

	if s.batch != nil {
		return s.batch.Add(s.pkt[:], dstIP)
	}
	return s.sender.SendTo(s.pkt[:], dstIP)
}

func (s *SYNSender) flush() error {
	if s.batch != nil {
		return s.batch.Flush()
	}
	return nil
}

// parseIPv4Fast parses an IPv4 dotted-decimal string directly into a
// [4]byte. Returns ok=false for IPv6, malformed input, or values > 255.
// Zero heap allocations.
func parseIPv4Fast(s string) (ip [4]byte, ok bool) {
	var octet, dots int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			octet = octet*10 + int(c-'0')
			if octet > 255 {
				return ip, false
			}
		case c == '.':
			if dots >= 3 {
				return ip, false
			}
			ip[dots] = byte(octet)
			dots++
			octet = 0
		default:
			return ip, false
		}
	}
	if dots != 3 {
		return ip, false
	}
	ip[3] = byte(octet)
	return ip, true
}

// targetIndex replaces PickIP's big.Int arithmetic with uint32 math.
// For IPv4 targets, computing an IP from a Blackrock index goes from
// ~3-5µs (big.Int + IntegerToIP + String) to ~10ns (uint32 add + shift).

// indexEntry represents one CIDR block in the target list.
type indexEntry struct {
	isV4     bool
	baseIPv4 uint32     // network base as uint32 (IPv4 only)
	count    int64      // number of addresses in this CIDR
	network  *net.IPNet // original, kept for IPv6 fallback
}

// targetIndex is a pre-computed lookup table that converts a linear
// index (as produced by Blackrock) into an IPv4 [4]byte address using
// pure uint32 arithmetic, no big.Int, no net.IP, no string conversion.
type targetIndex struct {
	entries []indexEntry
	total   int64
}

func buildTargetIndex(targets []*net.IPNet) *targetIndex {
	idx := &targetIndex{}
	for _, t := range targets {
		count := int64(mapcidr.AddressCountIpnet(t))
		e := indexEntry{
			count:   count,
			network: t,
		}
		if ip4 := t.IP.To4(); ip4 != nil {
			e.isV4 = true
			e.baseIPv4 = binary.BigEndian.Uint32(ip4)
		}
		idx.entries = append(idx.entries, e)
		idx.total += count
	}
	return idx
}

// pickIPv4 converts a global index to an IPv4 address. Returns the
// address as both a [4]byte (for the fast sender) and a string (for
// check functions that need map-key lookups).
//
// If the index maps to an IPv6 CIDR, isV4 is false and the caller
// should fall back to the standard PickIP/PickSubnetIP path.
//
// Cost: ~10ns + ~25ns string format = ~35ns total, zero heap allocs
// for the [4]byte path. (The string return does one small alloc.)
func (t *targetIndex) pickIPv4(index int64) (ip [4]byte, ipStr string, isV4 bool) {
	for i := range t.entries {
		e := &t.entries[i]
		if index < e.count {
			if !e.isV4 {
				return ip, "", false
			}
			val := e.baseIPv4 + uint32(index)
			ip[0] = byte(val >> 24)
			ip[1] = byte(val >> 16)
			ip[2] = byte(val >> 8)
			ip[3] = byte(val)
			ipStr = formatIPv4(ip)
			return ip, ipStr, true
		}
		index -= e.count
	}
	return ip, "", false
}

// formatIPv4 converts a [4]byte IPv4 address to its dotted-decimal
// string representation. ~25ns, one small heap alloc for the string.
func formatIPv4(ip [4]byte) string {
	// Max length: "255.255.255.255" = 15 bytes
	var buf [15]byte
	n := 0
	for i := 0; i < 4; i++ {
		if i > 0 {
			buf[n] = '.'
			n++
		}
		v := ip[i]
		if v >= 100 {
			buf[n] = v/100 + '0'
			n++
			buf[n] = (v/10)%10 + '0'
			n++
		} else if v >= 10 {
			buf[n] = v/10 + '0'
			n++
		}
		buf[n] = v%10 + '0'
		n++
	}
	return string(buf[:n])
}
