package probes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeDB_AddAndGet(t *testing.T) {
	db := NewProbeDB()

	probe := &Probe{
		Name:    "TestProbe",
		Payload: "\x01\x02\x03",
		Rarity:  1,
	}
	db.AddProbe(probe, 53)

	probes := db.GetProbesForPort(53)
	require.Len(t, probes, 1)
	assert.Equal(t, "TestProbe", probes[0].Name)
}

func TestProbeDB_GetProbesForPort_NotFound(t *testing.T) {
	db := NewProbeDB()
	probes := db.GetProbesForPort(9999)
	assert.Nil(t, probes)
}

func TestProbeDB_MultiPortProbe(t *testing.T) {
	db := NewProbeDB()

	probe := &Probe{
		Name:    "MultiPort",
		Payload: "\x00",
		Rarity:  1,
	}
	db.AddProbe(probe, 53, 69, 5353)

	// Should appear in all three ports
	for _, port := range []int{53, 69, 5353} {
		probes := db.GetProbesForPort(port)
		require.Len(t, probes, 1, "port %d should have 1 probe", port)
		assert.Equal(t, "MultiPort", probes[0].Name)
	}
}

func TestProbeDB_SortProbes(t *testing.T) {
	db := NewProbeDB()

	// Add probes in non-sorted order
	db.AddProbe(&Probe{Name: "High", Rarity: 5}, 123)
	db.AddProbe(&Probe{Name: "Low", Rarity: 1}, 123)
	db.AddProbe(&Probe{Name: "Medium", Rarity: 3}, 123)

	db.SortProbes()

	probes := db.GetProbesForPort(123)
	require.Len(t, probes, 3)

	expected := []struct {
		name   string
		rarity int
	}{
		{"Low", 1},
		{"Medium", 3},
		{"High", 5},
	}

	for i, exp := range expected {
		assert.Equal(t, exp.name, probes[i].Name, "position %d", i)
		assert.Equal(t, exp.rarity, probes[i].Rarity, "position %d", i)
	}
}

func TestProbeDB_SortProbes_MultiplePortsIndependent(t *testing.T) {
	db := NewProbeDB()

	// Add different probes to different ports
	db.AddProbe(&Probe{Name: "DNS-High", Rarity: 5}, 53)
	db.AddProbe(&Probe{Name: "DNS-Low", Rarity: 1}, 53)
	db.AddProbe(&Probe{Name: "NTP-Med", Rarity: 3}, 123)
	db.AddProbe(&Probe{Name: "NTP-Low", Rarity: 2}, 123)

	db.SortProbes()

	// Check DNS probes
	dnsProbes := db.GetProbesForPort(53)
	require.Len(t, dnsProbes, 2)
	assert.Equal(t, "DNS-Low", dnsProbes[0].Name)
	assert.Equal(t, "DNS-High", dnsProbes[1].Name)

	// Check NTP probes
	ntpProbes := db.GetProbesForPort(123)
	require.Len(t, ntpProbes, 2)
	assert.Equal(t, "NTP-Low", ntpProbes[0].Name)
	assert.Equal(t, "NTP-Med", ntpProbes[1].Name)
}

func TestLoadEmbeddedProbes(t *testing.T) {
	db := LoadEmbeddedProbes()

	// Should have probes for common ports
	expectedPorts := []int{53, 123, 161, 623, 1194, 1900, 5060, 5246}
	for _, port := range expectedPorts {
		probes := db.GetProbesForPort(port)
		assert.NotEmpty(t, probes, "expected probes for port %d", port)
	}
}

func TestLoadEmbeddedProbes_Sorted(t *testing.T) {
	db := LoadEmbeddedProbes()

	// Check that probes are sorted by rarity for ports with multiple probes
	// Port 161 (SNMP) has SNMPv1public (rarity 1), SNMPv2c (rarity 1), SNMPv3GetRequest (rarity 2)
	snmpProbes := db.GetProbesForPort(161)
	require.GreaterOrEqual(t, len(snmpProbes), 3)

	for i := 1; i < len(snmpProbes); i++ {
		assert.LessOrEqual(t, snmpProbes[i-1].Rarity, snmpProbes[i].Rarity,
			"probes should be sorted: %s (rarity %d) should come before %s (rarity %d)",
			snmpProbes[i-1].Name, snmpProbes[i-1].Rarity,
			snmpProbes[i].Name, snmpProbes[i].Rarity)
	}
}

func TestLoadEmbeddedProbes_PayloadsNotEmpty(t *testing.T) {
	db := LoadEmbeddedProbes()

	// Spot check a few probes have non-empty payloads
	tests := []struct {
		port int
		name string
	}{
		{123, "NTPRequest"},
		{161, "SNMPv1public"},
		{161, "SNMPv2c"},
		{1194, "OpenVPN"},
		{1900, "SSDP-MSEARCH"},
		{5246, "DTLS-ClientHello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probes := db.GetProbesForPort(tt.port)
			var found *Probe
			for _, p := range probes {
				if p.Name == tt.name {
					found = p
					break
				}
			}
			require.NotNil(t, found, "probe %s not found for port %d", tt.name, tt.port)
			assert.NotEmpty(t, found.Payload, "probe %s has empty payload", tt.name)
		})
	}
}
