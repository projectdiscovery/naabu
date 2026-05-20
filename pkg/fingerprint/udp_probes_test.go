package fingerprint

import (
	"bytes"
	"testing"
)

func newDNSProbe(rarity int, ports ...int) *ServiceProbe {
	ps := NewPortSet()
	for _, p := range ports {
		ps.Add(p)
	}
	return &ServiceProbe{
		Protocol: "UDP",
		Name:     "DNSVersionBindReq",
		Data:     []byte{0x00, 0x06, 0x01, 0x00, 0x00, 0x01},
		Ports:    ps,
		Rarity:   rarity,
	}
}

func newSNMPProbe(rarity int, ports ...int) *ServiceProbe {
	ps := NewPortSet()
	for _, p := range ports {
		ps.Add(p)
	}
	return &ServiceProbe{
		Protocol: "UDP",
		Name:     "SNMPv1public",
		Data:     []byte{0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c'},
		Ports:    ps,
		Rarity:   rarity,
	}
}

// TestUDPProbesForPortReturnsOnlyMatchingPort pins that probes without
// the target port are filtered out, so the scanner never sends DNS
// bytes to an SNMP port (or vice-versa).
func TestUDPProbesForPortReturnsOnlyMatchingPort(t *testing.T) {
	db := &ProbeDB{
		Probes: []*ServiceProbe{
			newDNSProbe(1, 53),
			newSNMPProbe(2, 161, 162),
		},
	}
	dns := db.UDPProbesForPort(53)
	if len(dns) != 1 || dns[0].Name != "DNSVersionBindReq" {
		t.Fatalf("expected DNS probe for :53, got %+v", dns)
	}
	snmp := db.UDPProbesForPort(161)
	if len(snmp) != 1 || snmp[0].Name != "SNMPv1public" {
		t.Fatalf("expected SNMP probe for :161, got %+v", snmp)
	}
	if got := db.UDPProbesForPort(7); len(got) != 0 {
		t.Fatalf("expected no probes for :7, got %+v", got)
	}
}

// TestUDPProbesForPortOrderedByRarity confirms that the lowest-rarity
// (most common) probe wins so we don't blow the budget on obscure
// services first.
func TestUDPProbesForPortOrderedByRarity(t *testing.T) {
	common := newDNSProbe(1, 53)
	common.Name = "Common"
	rare := newDNSProbe(8, 53)
	rare.Name = "Rare"
	db := &ProbeDB{Probes: []*ServiceProbe{rare, common}}

	got := db.UDPProbesForPort(53)
	if len(got) != 2 {
		t.Fatalf("expected 2 probes, got %d", len(got))
	}
	if got[0].Name != "Common" || got[1].Name != "Rare" {
		t.Fatalf("probes out of order: %s, %s", got[0].Name, got[1].Name)
	}
}

// TestUDPProbesForPortSkipsTCPAndEmpty guarantees that TCP entries and
// probes with empty payloads (the "NULL" probe family) never reach the
// UDP scan path.
func TestUDPProbesForPortSkipsTCPAndEmpty(t *testing.T) {
	tcpProbe := newDNSProbe(1, 53)
	tcpProbe.Protocol = "TCP"

	empty := newDNSProbe(1, 53)
	empty.Data = nil

	db := &ProbeDB{Probes: []*ServiceProbe{tcpProbe, empty}}
	if got := db.UDPProbesForPort(53); len(got) != 0 {
		t.Fatalf("expected no usable probes, got %+v", got)
	}
}

// TestUDPProbeForPortHappyPath checks the convenience accessor used by
// the scan path: it must return the bytes of the highest-priority
// probe.
func TestUDPProbeForPortHappyPath(t *testing.T) {
	db := &ProbeDB{Probes: []*ServiceProbe{newDNSProbe(1, 53)}}
	payload := db.UDPProbeForPort(53)
	want := []byte{0x00, 0x06, 0x01, 0x00, 0x00, 0x01}
	if !bytes.Equal(payload, want) {
		t.Fatalf("UDPProbeForPort(53) = %x, want %x", payload, want)
	}
}

// TestUDPProbeForPortMissing documents that an empty result means "no
// probe configured" - callers must treat this as the signal to fall
// back to the legacy empty-payload behavior.
func TestUDPProbeForPortMissing(t *testing.T) {
	db := &ProbeDB{}
	if got := db.UDPProbeForPort(53); got != nil {
		t.Fatalf("expected nil for empty DB, got %x", got)
	}
}

// TestUDPProbeForPortNilDB pins the nil-receiver contract: when the
// runner could not load nmap-service-probes the *ProbeDB is nil, and
// the scan path must still work.
func TestUDPProbeForPortNilDB(t *testing.T) {
	var db *ProbeDB
	if got := db.UDPProbeForPort(53); got != nil {
		t.Fatalf("expected nil result from nil DB, got %x", got)
	}
	if got := db.UDPProbesForPort(53); got != nil {
		t.Fatalf("expected nil slice from nil DB, got %+v", got)
	}
}
