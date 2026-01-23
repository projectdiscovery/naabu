// Package probes provides UDP service detection probes for port scanning.
//
// UDP scanning is inherently difficult because the protocol is connectionless.
// Unlike TCP where a SYN-ACK confirms an open port, UDP services only respond
// if they receive a valid protocol-specific request. Sending arbitrary data
// typically results in silence (indistinguishable from a filtered port) or
// an ICMP "port unreachable" message (indicating closed).
//
// This package embeds protocol-specific probes derived from nmap's
// nmap-service-probes database. When scanning a UDP port, the appropriate
// probe is sent to elicit a response from the service, confirming the port
// is open.
//
// Reference: https://nmap.org/book/vscan-fileformat.html
package probes

import "sort"

// Probe represents a UDP service probe
type Probe struct {
	Name    string // Probe name (for logging/debugging)
	Payload string // Raw bytes to send (stored as string for efficient use with ConnectPort)
	Rarity  int    // 1-9, lower = more common/tried first (matches nmap)
}

// ProbeDB holds probes indexed by port
type ProbeDB struct {
	portProbes map[int][]*Probe // port -> probes
}

// NewProbeDB creates a new empty probe database
func NewProbeDB() *ProbeDB {
	return &ProbeDB{
		portProbes: make(map[int][]*Probe),
	}
}

// AddProbe adds a probe for the given ports
func (db *ProbeDB) AddProbe(probe *Probe, ports ...int) {
	for _, port := range ports {
		db.portProbes[port] = append(db.portProbes[port], probe)
	}
}

// SortProbes sorts all probe lists by rarity (lowest first)
func (db *ProbeDB) SortProbes() {
	for port := range db.portProbes {
		sort.Slice(db.portProbes[port], func(i, j int) bool {
			return db.portProbes[port][i].Rarity < db.portProbes[port][j].Rarity
		})
	}
}

// GetProbesForPort returns all probes for a given port, sorted by rarity
// (lowest rarity = most common, tried first). Returns nil if no probes exist.
func (db *ProbeDB) GetProbesForPort(port int) []*Probe {
	return db.portProbes[port]
}
