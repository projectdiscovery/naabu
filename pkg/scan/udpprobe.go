package scan

import (
	"sync/atomic"

	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
)

// UDPProbeProvider returns the UDP payload that should be sent when
// scanning a given destination port. Implementations must be safe for
// use from multiple goroutines. Returning nil or an empty slice signals
// "no probe known for this port" and the scan path falls back to its
// historical behavior of sending an empty UDP datagram.
type UDPProbeProvider interface {
	UDPProbe(port int) []byte
}

// nopUDPProbeProvider is the default until the runner installs a real
// provider. It keeps the legacy "send an empty UDP datagram" behavior
// so existing callers see no change.
type nopUDPProbeProvider struct{}

func (nopUDPProbeProvider) UDPProbe(int) []byte { return nil }

// udpProbeProvider holds the currently-installed provider behind an
// atomic pointer so SetUDPProbeProvider can be called from any
// goroutine without locking the scan hot path. atomic.Pointer is used
// rather than atomic.Value because callers swap in providers of
// different concrete types, which Value rejects.
var udpProbeProvider atomic.Pointer[UDPProbeProvider]

func init() {
	var noop UDPProbeProvider = nopUDPProbeProvider{}
	udpProbeProvider.Store(&noop)
}

// SetUDPProbeProvider installs the global UDP probe provider used by
// the raw UDP send path and by ConnectPort when the caller passes an
// empty payload. Passing nil restores the no-op provider.
func SetUDPProbeProvider(p UDPProbeProvider) {
	if p == nil {
		var noop UDPProbeProvider = nopUDPProbeProvider{}
		udpProbeProvider.Store(&noop)
		return
	}
	udpProbeProvider.Store(&p)
}

// GetUDPProbeProvider returns the currently-installed provider. It is
// never nil.
func GetUDPProbeProvider() UDPProbeProvider {
	if p := udpProbeProvider.Load(); p != nil {
		return *p
	}
	return nopUDPProbeProvider{}
}

// udpProbePayload is the indirection point that send paths call. It
// returns the bytes to put in the UDP datagram for the given port, or
// nil when no probe is configured.
func udpProbePayload(port int) []byte {
	return GetUDPProbeProvider().UDPProbe(port)
}

// udpLayersWithProbe assembles the serialize-layer slice handed to
// sendWithConn. When the active provider returns a non-empty probe
// for the destination port we append it as the UDP payload so the
// resulting datagram is no longer a zero-length probe. Returning a
// slice (rather than mutating sendWithConn's signature) keeps the
// hot-path call sites readable and lets a no-op provider stay
// allocation-free.
func udpLayersWithProbe(udp *layers.UDP, port int) []gopacket.SerializableLayer {
	payload := udpProbePayload(port)
	if len(payload) == 0 {
		return []gopacket.SerializableLayer{udp}
	}
	return []gopacket.SerializableLayer{udp, gopacket.Payload(payload)}
}
