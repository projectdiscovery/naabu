package runner

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	// defaultSrcSum is the checksum contribution of the default-route source
	// IP, used as a fallback when a destination has no resolvable per-route
	// source (see send).
	defaultSrcSum uint32
	// pinnedSrcSum, when non-zero, overrides the per-target source checksum
	// term: the socket is bound to a fixed -source-ip, so every packet is
	// emitted with that source and must checksum against it.
	pinnedSrcSum uint32
	pkt          [24]byte
}

const (
	// synPacketLen is the fixed size of the SYN template (20 byte TCP header +
	// 4 byte MSS option).
	synPacketLen = 24
	// synBatchSize is the number of packets accumulated before a sendmmsg call.
	// Capped at the kernel's UIO_MAXIOV (1024); partial sends are retried by
	// rawsend.Batch.Flush.
	synBatchSize = 1024
)

var (
	errNoRawConn    = errors.New("no raw IPv4 connection")
	errEthernetPath = errors.New("ethernet framing path requires standard sender")
	errNoSourceIP   = errors.New("cannot determine source IP")
)

// wantsEthernetPath reports whether a scan must use the L2 (ethernet) send path
// instead of the fast sender: only when a source IP is pinned (with an interface
// MAC) but the raw socket could not be bound to it, i.e. a spoofed/non-owned
// source. A successfully bound source is emitted by the kernel directly, so the
// fast path stays in use.
func wantsEthernetPath(handler *scan.ListenHandler) bool {
	return handler.SourceIp4 != nil && handler.SourceHW != nil && !handler.SourceBound
}

func newSYNSender(handler *scan.ListenHandler) (*SYNSender, error) {
	if handler == nil || handler.TcpConn4 == nil {
		return nil, errNoRawConn
	}
	// Hand off to the L2 (ethernet) path only when a source IP is pinned but the
	// socket could not be bound to it (e.g. spoofed/non-owned source). When the
	// bind succeeded the kernel already emits the chosen source, so the fast
	// path is both correct and preferred over the fragile L2 path.
	if wantsEthernetPath(handler) {
		return nil, errEthernetPath
	}

	var srcIP net.IP
	if handler.SourceIp4 != nil {
		srcIP = handler.SourceIp4
	} else if scan.PkgRouter != nil {
		var routeErr error
		_, _, srcIP, routeErr = scan.PkgRouter.Route(net.IPv4(1, 1, 1, 1))
		if routeErr != nil {
			return nil, fmt.Errorf("route lookup failed: %w", routeErr)
		}
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
		sender: sender,
		// Batch up to UIO_MAXIOV (1024) packets per sendmmsg call. At high
		// packet rates this is the dominant syscall-amortisation lever: a 32
		// packet batch issued ~32x more sendmmsg calls for the same throughput.
		batch:         rawsend.NewBatch(sender.FD(), synBatchSize, synPacketLen),
		srcPort:       uint16(handler.Port),
		defaultSrcSum: ipChecksumSum(src4),
	}
	// When the socket is bound to an explicit -source-ip the kernel emits every
	// packet with it, so pin the checksum's source term to that address instead
	// of the per-target route source.
	if handler.SourceBound && handler.SourceIp4 != nil {
		s.pinnedSrcSum = ipChecksumSum(src4)
	}

	binary.BigEndian.PutUint16(s.pkt[0:2], s.srcPort)
	s.pkt[12] = 0x60 // DataOffset: 6 words (24 bytes)
	s.pkt[13] = 0x02 // Flags: SYN
	binary.BigEndian.PutUint16(s.pkt[14:16], 1024)
	s.pkt[20] = 2 // MSS option kind
	s.pkt[21] = 4 // MSS option length
	binary.BigEndian.PutUint16(s.pkt[22:24], 1460)

	// The source IP is intentionally NOT folded into baseSum here: the kernel
	// picks the source address per destination route (e.g. 127.0.0.1 for a
	// loopback target, a different NIC for another subnet), so the pseudo-header
	// source term is added per packet in send() from the destination's route.
	var sum uint32
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

// ipChecksumSum returns the two 16-bit words of an IPv4 address added together,
// i.e. its contribution to a TCP pseudo-header checksum (not yet folded).
func ipChecksumSum(ip4 net.IP) uint32 {
	if len(ip4) != 4 {
		return 0
	}
	return uint32(binary.BigEndian.Uint16(ip4[0:2])) + uint32(binary.BigEndian.Uint16(ip4[2:4]))
}

// send transmits a SYN to dstIP:dstPort. srcSum is the pseudo-header checksum
// contribution of the source IP the kernel will use for this destination (as
// returned by targetIndex.pickIPv4); a zero srcSum falls back to the default
// route source so the checksum still matches a single-homed setup.
func (s *SYNSender) send(dstIP [4]byte, srcSum uint32, dstPort uint16) error {
	srcSum = s.effectiveSrcSum(srcSum)
	// Encode a SYN cookie into the sequence number so the receive path can
	// verify the returning SYN-ACK (Ack == seq+1) is genuinely ours.
	seq := scan.SynCookie4(dstIP, dstPort, s.srcPort)

	binary.BigEndian.PutUint16(s.pkt[2:4], dstPort)
	binary.BigEndian.PutUint32(s.pkt[4:8], seq)

	binary.BigEndian.PutUint16(s.pkt[16:18], synTCPChecksum(s.baseSum, srcSum, dstIP, dstPort, seq))

	if s.batch != nil {
		return s.batch.Add(s.pkt[:], dstIP)
	}
	return s.sender.SendTo(s.pkt[:], dstIP)
}

// effectiveSrcSum resolves the source pseudo-header checksum term for a packet:
// a pinned bound source wins over the per-target route source, which in turn
// wins over the default-route fallback.
func (s *SYNSender) effectiveSrcSum(srcSum uint32) uint32 {
	if s.pinnedSrcSum != 0 {
		return s.pinnedSrcSum
	}
	if srcSum == 0 {
		return s.defaultSrcSum
	}
	return srcSum
}

// synTCPChecksum folds the precomputed constant terms (baseSum) with the
// per-packet source pseudo-header term (srcSum), destination IP, destination
// port and sequence number into the final TCP checksum for the SYN template.
func synTCPChecksum(baseSum, srcSum uint32, dstIP [4]byte, dstPort uint16, seq uint32) uint16 {
	sum := baseSum + srcSum +
		uint32(binary.BigEndian.Uint16(dstIP[0:2])) +
		uint32(binary.BigEndian.Uint16(dstIP[2:4])) +
		uint32(dstPort) +
		uint32(seq>>16) +
		uint32(seq&0xffff)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
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
	// srcSum is the pseudo-header checksum contribution of the source IP the
	// kernel uses to reach this CIDR (resolved once at build time). Targets on
	// different routes (loopback, other NICs) need different source IPs for a
	// correct TCP checksum.
	srcSum uint32
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
	defaultSrcSum := routeSrcSum(net.IPv4(1, 1, 1, 1))
	for _, t := range targets {
		count := int64(mapcidr.AddressCountIpnet(t))
		e := indexEntry{
			count:   count,
			network: t,
		}
		if ip4 := t.IP.To4(); ip4 != nil {
			e.isV4 = true
			e.baseIPv4 = binary.BigEndian.Uint32(ip4)
			// Resolve the source IP for this CIDR's route so the fast sender's
			// TCP checksum matches the source the kernel actually emits with.
			e.srcSum = routeSrcSum(t.IP)
			if e.srcSum == 0 {
				e.srcSum = defaultSrcSum
			}
		}
		idx.entries = append(idx.entries, e)
		idx.total += count
	}
	return idx
}

// routeSrcSum resolves the source IP the kernel would use to reach dst and
// returns its pseudo-header checksum contribution, or 0 if it cannot be
// resolved (no router, route error, or IPv6 source).
func routeSrcSum(dst net.IP) uint32 {
	if scan.PkgRouter == nil {
		return 0
	}
	_, _, src, err := scan.PkgRouter.Route(dst)
	if err != nil || src == nil {
		return 0
	}
	return ipChecksumSum(src.To4())
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
func (t *targetIndex) pickIPv4(index int64) (ip [4]byte, ipStr string, srcSum uint32, isV4 bool) {
	for i := range t.entries {
		e := &t.entries[i]
		if index < e.count {
			if !e.isV4 {
				return ip, "", 0, false
			}
			val := e.baseIPv4 + uint32(index)
			ip[0] = byte(val >> 24)
			ip[1] = byte(val >> 16)
			ip[2] = byte(val >> 8)
			ip[3] = byte(val)
			ipStr = formatIPv4(ip)
			return ip, ipStr, e.srcSum, true
		}
		index -= e.count
	}
	return ip, "", 0, false
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
