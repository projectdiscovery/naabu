package scan

import (
	"github.com/Mzack9999/gopacket/layers"
)

// isDecoySynAck reports whether a SYN-ACK looks like an on-path SYN-proxy /
// tarpit decoy rather than a genuine listening service.
//
// Observed middleboxes (rate-triggered firewalls, SYN flood mitigations) answer
// probes with a minimal SYN-ACK: window 0 and no TCP options (a bare 20-byte
// header). Real stacks almost always advertise a non-zero window and at least
// an MSS option. Dropping these decoys before recording an open port stops
// wide SYN scans from inventing thousands of false positives when the path
// starts forging replies under load.
//
// The check is intentionally narrow. A SYN-ACK with window 0 *and* options, or
// a non-zero window with no options, is left alone - only the combination that
// matched every forged reply in capture against such devices is rejected.
func isDecoySynAck(tcp layers.TCP) bool {
	if tcp.Window != 0 {
		return false
	}
	// DataOffset is in 32-bit words; 5 => 20-byte header => no options.
	// Prefer the Options slice when the parser populated it, but also trust
	// DataOffset in case Options was left empty by a partial decode.
	if len(tcp.Options) > 0 {
		return false
	}
	if tcp.DataOffset != 0 && tcp.DataOffset > 5 {
		return false
	}
	return true
}
