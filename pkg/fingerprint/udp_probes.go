package fingerprint

import "sort"

// UDPProbesForPort returns every UDP probe from the loaded probe DB
// whose declared ports include targetPort, ordered by ascending Rarity
// (most common first). Probes that do not list any port are skipped:
// the port-scan path only sends bytes when nmap explicitly hinted that
// they belong on this destination. The slice is empty when the DB is
// nil or when no probe applies, in which case callers fall back to
// whatever default they want (typically: empty UDP payload).
//
// The returned probes are owned by the ProbeDB and must not be mutated.
func (db *ProbeDB) UDPProbesForPort(targetPort int) []*ServiceProbe {
	if db == nil {
		return nil
	}
	var matches []*ServiceProbe
	for _, sp := range db.Probes {
		if sp.Protocol != "UDP" {
			continue
		}
		if sp.Ports == nil || !sp.Ports.Contains(targetPort) {
			continue
		}
		if len(sp.Data) == 0 {
			continue
		}
		matches = append(matches, sp)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].Rarity < matches[j].Rarity
	})
	return matches
}

// UDPProbeForPort returns the payload of the highest-priority UDP
// probe that targets the given port. It returns nil when no probe
// applies, signalling to the caller that the legacy empty-payload
// behavior should be kept.
func (db *ProbeDB) UDPProbeForPort(targetPort int) []byte {
	probes := db.UDPProbesForPort(targetPort)
	if len(probes) == 0 {
		return nil
	}
	return probes[0].Data
}
