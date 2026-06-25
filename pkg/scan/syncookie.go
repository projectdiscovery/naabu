package scan

import (
	"crypto/rand"
	"encoding/binary"
	"net"
)

// synCookieKey is a per-process random key used to derive the TCP sequence
// number ("SYN cookie") of outbound SYN probes. The matching SYN-ACK echoes
// it back as Ack = seq+1, which lets the receive path confirm a reply is
// genuinely ours - rejecting spoofed, injected or stale SYN-ACKs that happen
// to originate from an address in the target set.
var synCookieKey = func() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a fixed constant; validation still works for a single
		// run, it is just predictable across runs.
		return 0x9E3779B97F4A7C15
	}
	return binary.BigEndian.Uint64(b[:])
}()

// SynCookie derives the 32-bit sequence number for a SYN probe toward
// dstIP:dstPort sent from local port srcPort. The mix is keyed and
// non-cryptographic (splitmix64-style finaliser) - chosen for speed on the
// send hot path; it only needs to be hard to guess blindly, not collision
// proof.
func SynCookie(dstIP net.IP, dstPort, srcPort uint16) uint32 {
	x := synCookieKey
	if ip4 := dstIP.To4(); ip4 != nil {
		x ^= uint64(binary.BigEndian.Uint32(ip4))
	} else if ip16 := dstIP.To16(); ip16 != nil {
		x ^= binary.BigEndian.Uint64(ip16[0:8])
		x ^= binary.BigEndian.Uint64(ip16[8:16])
	}
	return synCookieMix(x, dstPort, srcPort)
}

// SynCookie4 is the zero-allocation variant for the fast IPv4 sender.
func SynCookie4(dstIP [4]byte, dstPort, srcPort uint16) uint32 {
	x := synCookieKey ^ uint64(binary.BigEndian.Uint32(dstIP[:]))
	return synCookieMix(x, dstPort, srcPort)
}

func synCookieMix(x uint64, dstPort, srcPort uint16) uint32 {
	x ^= uint64(dstPort)<<16 | uint64(srcPort)
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return uint32(x)
}

// verifySynCookie reports whether a received SYN-ACK acknowledges a SYN we
// actually sent. targetPort is the responder's source port (the port we
// probed) and ourPort is the local listening port; ack is the SYN-ACK
// acknowledgement number, which must equal our sent seq+1.
func verifySynCookie(srcIP4, srcIP6 string, targetPort, ourPort uint16, ack uint32) bool {
	ipStr := srcIP4
	if ipStr == "" {
		ipStr = srcIP6
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ack-1 == SynCookie(ip, targetPort, ourPort)
}
