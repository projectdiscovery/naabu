package scan

import (
	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
)

// UDPProbeProvider returns the UDP payload that should be sent when
// scanning a given destination port. Implementations must be safe for
// use from multiple goroutines. Returning nil or an empty slice signals
// "no probe known for this port" and the scan path falls back to its
// historical behavior of sending an empty UDP datagram.
//
// Providers are installed per *Scanner via Scanner.SetUDPProbeProvider
// rather than as a process-global, so concurrent scanners can carry
// independent probe behavior without clobbering each other.
type UDPProbeProvider interface {
	UDPProbe(port int) []byte
}

// udpProbePayload returns the bytes the configured provider wants for
// the destination port, or nil when no provider is installed. The
// nil-receiver and nil-provider cases collapse to the same "no probe"
// signal so callers never have to nil-check before calling.
func (s *Scanner) udpProbePayload(port int) []byte {
	if s == nil || s.UDPProbeProvider == nil {
		return nil
	}
	return s.UDPProbeProvider.UDPProbe(port)
}

// udpProbePayload is the raw-send-path counterpart of the Scanner
// helper: sendAsyncUDP4/6 only have a *ListenHandler in scope, so the
// provider rides on the handler. NewScanner copies the scanner's
// provider into the handler once the handler is acquired.
func (l *ListenHandler) udpProbePayload(port int) []byte {
	if l == nil || l.UDPProbeProvider == nil {
		return nil
	}
	return l.UDPProbeProvider.UDPProbe(port)
}

// udpLayersWithProbe assembles the serialize-layer slice handed to
// sendWithConn. When the handler's provider returns a non-empty
// payload for the destination port we append it as the UDP payload so
// the resulting datagram is no longer a zero-length probe. Returning
// a slice (rather than mutating sendWithConn's signature) keeps the
// hot-path call sites readable and lets a missing provider stay
// allocation-free.
func (l *ListenHandler) udpLayersWithProbe(udp *layers.UDP, port int) []gopacket.SerializableLayer {
	payload := l.udpProbePayload(port)
	if len(payload) == 0 {
		return []gopacket.SerializableLayer{udp}
	}
	return []gopacket.SerializableLayer{udp, gopacket.Payload(payload)}
}

// SetUDPProbeProvider installs the provider used by the raw UDP send
// path and by ConnectPort when the caller passes an empty payload.
// Passing nil disables UDP probing for this scanner; subsequent UDP
// scans send the historical zero-length datagram. The change is
// propagated to the scanner's ListenHandler so the raw send path
// (sendAsyncUDP4/6) sees it without needing to look at the scanner.
func (s *Scanner) SetUDPProbeProvider(p UDPProbeProvider) {
	if s == nil {
		return
	}
	s.UDPProbeProvider = p
	if s.ListenHandler != nil {
		s.ListenHandler.UDPProbeProvider = p
	}
}
