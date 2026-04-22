package runner

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseIPv4Fast(t *testing.T) {
	tests := []struct {
		input    string
		expected [4]byte
		ok       bool
	}{
		{"192.168.1.1", [4]byte{192, 168, 1, 1}, true},
		{"0.0.0.0", [4]byte{0, 0, 0, 0}, true},
		{"255.255.255.255", [4]byte{255, 255, 255, 255}, true},
		{"10.0.0.1", [4]byte{10, 0, 0, 1}, true},
		{"1.1.1.1", [4]byte{1, 1, 1, 1}, true},
		{"256.0.0.1", [4]byte{}, false},
		{"1.2.3", [4]byte{}, false},
		{"1.2.3.4.5", [4]byte{}, false},
		{"::1", [4]byte{}, false},
		{"abc", [4]byte{}, false},
		{"", [4]byte{}, false},
	}

	for _, tt := range tests {
		ip, ok := parseIPv4Fast(tt.input)
		if ok != tt.ok {
			t.Errorf("parseIPv4Fast(%q): got ok=%v, want %v", tt.input, ok, tt.ok)
			continue
		}
		if ok && ip != tt.expected {
			t.Errorf("parseIPv4Fast(%q): got %v, want %v", tt.input, ip, tt.expected)
		}
	}
}

func TestSYNPacketChecksum(t *testing.T) {
	// Manually compute the expected checksum for a known packet
	// and verify our incremental approach matches.
	srcIP := [4]byte{192, 168, 1, 100}
	dstIP := [4]byte{10, 0, 0, 1}
	srcPort := uint16(12345)
	dstPort := uint16(80)
	seq := uint32(42)

	// Full checksum computation (reference implementation)
	var fullSum uint32
	// Pseudo-header
	fullSum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	fullSum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	fullSum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	fullSum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	fullSum += 6  // protocol
	fullSum += 24 // TCP length
	// TCP header words
	fullSum += uint32(srcPort)
	fullSum += uint32(dstPort)
	fullSum += uint32(seq >> 16)
	fullSum += uint32(seq & 0xffff)
	fullSum += 0      // ack high
	fullSum += 0      // ack low
	fullSum += 0x6002 // data offset + SYN
	fullSum += 0x0400 // window
	fullSum += 0      // checksum (zeroed)
	fullSum += 0      // urgent
	fullSum += 0x0204 // MSS kind+len
	fullSum += 0x05B4 // MSS value
	fullSum = (fullSum >> 16) + (fullSum & 0xffff)
	fullSum += fullSum >> 16
	expectedChecksum := ^uint16(fullSum)

	// Incremental computation (our fast path)
	var baseSum uint32
	baseSum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	baseSum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	baseSum += 6
	baseSum += 24
	baseSum += uint32(srcPort)
	baseSum += 0x6002
	baseSum += 0x0400
	baseSum += 0x0204
	baseSum += 0x05B4

	sum := baseSum +
		uint32(binary.BigEndian.Uint16(dstIP[0:2])) +
		uint32(binary.BigEndian.Uint16(dstIP[2:4])) +
		uint32(dstPort) +
		uint32(seq>>16) +
		uint32(seq&0xffff)
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	gotChecksum := ^uint16(sum)

	if gotChecksum != expectedChecksum {
		t.Errorf("checksum mismatch: incremental=0x%04x, reference=0x%04x", gotChecksum, expectedChecksum)
	}
}

func TestFormatIPv4(t *testing.T) {
	tests := []struct {
		ip       [4]byte
		expected string
	}{
		{[4]byte{192, 168, 1, 1}, "192.168.1.1"},
		{[4]byte{0, 0, 0, 0}, "0.0.0.0"},
		{[4]byte{255, 255, 255, 255}, "255.255.255.255"},
		{[4]byte{10, 0, 0, 1}, "10.0.0.1"},
		{[4]byte{1, 2, 3, 4}, "1.2.3.4"},
		{[4]byte{100, 200, 30, 4}, "100.200.30.4"},
	}
	for _, tt := range tests {
		got := formatIPv4(tt.ip)
		if got != tt.expected {
			t.Errorf("formatIPv4(%v) = %q, want %q", tt.ip, got, tt.expected)
		}
	}
}

func TestTargetIndex(t *testing.T) {
	_, cidr24, _ := net.ParseCIDR("192.168.1.0/24")
	_, cidr16, _ := net.ParseCIDR("10.0.0.0/16")

	idx := buildTargetIndex([]*net.IPNet{cidr24, cidr16})

	// First CIDR: 192.168.1.0/24 -> 256 addresses
	ip, ipStr, ok := idx.pickIPv4(0)
	if !ok || ip != [4]byte{192, 168, 1, 0} || ipStr != "192.168.1.0" {
		t.Errorf("index 0: got ip=%v str=%q ok=%v", ip, ipStr, ok)
	}

	ip, ipStr, ok = idx.pickIPv4(255)
	if !ok || ip != [4]byte{192, 168, 1, 255} || ipStr != "192.168.1.255" {
		t.Errorf("index 255: got ip=%v str=%q ok=%v", ip, ipStr, ok)
	}

	// Second CIDR starts at index 256: 10.0.0.0/16
	ip, ipStr, ok = idx.pickIPv4(256)
	if !ok || ip != [4]byte{10, 0, 0, 0} || ipStr != "10.0.0.0" {
		t.Errorf("index 256: got ip=%v str=%q ok=%v", ip, ipStr, ok)
	}

	ip, ipStr, ok = idx.pickIPv4(256 + 65535)
	if !ok || ip != [4]byte{10, 0, 255, 255} || ipStr != "10.0.255.255" {
		t.Errorf("index 256+65535: got ip=%v str=%q ok=%v", ip, ipStr, ok)
	}

	// Out of range
	_, _, ok = idx.pickIPv4(256 + 65536)
	if ok {
		t.Error("expected ok=false for out-of-range index")
	}
}

func TestFormatIPv4RoundTrip(t *testing.T) {
	// Verify formatIPv4 and parseIPv4Fast are inverses.
	ips := [][4]byte{
		{0, 0, 0, 0}, {1, 2, 3, 4}, {10, 0, 0, 1},
		{192, 168, 1, 100}, {255, 255, 255, 255},
	}
	for _, ip := range ips {
		s := formatIPv4(ip)
		parsed, ok := parseIPv4Fast(s)
		if !ok || parsed != ip {
			t.Errorf("round-trip failed: %v -> %q -> %v (ok=%v)", ip, s, parsed, ok)
		}
	}
}

func BenchmarkParseIPv4Fast(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseIPv4Fast("192.168.1.1")
	}
}

func BenchmarkFormatIPv4(b *testing.B) {
	ip := [4]byte{192, 168, 1, 100}
	for i := 0; i < b.N; i++ {
		_ = formatIPv4(ip)
	}
}

func BenchmarkTargetIndexPickIPv4(b *testing.B) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	idx := buildTargetIndex([]*net.IPNet{cidr})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.pickIPv4(int64(i) % idx.total)
	}
}

func BenchmarkSYNChecksum(b *testing.B) {
	srcIP := [4]byte{192, 168, 1, 100}
	var baseSum uint32
	baseSum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	baseSum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	baseSum += 6 + 24 + 12345 + 0x6002 + 0x0400 + 0x0204 + 0x05B4

	dstIP := [4]byte{10, 0, 0, 1}
	dstPort := uint16(80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint32(i)
		sum := baseSum +
			uint32(binary.BigEndian.Uint16(dstIP[0:2])) +
			uint32(binary.BigEndian.Uint16(dstIP[2:4])) +
			uint32(dstPort) +
			uint32(seq>>16) +
			uint32(seq&0xffff)
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		_ = ^uint16(sum)
	}
}
