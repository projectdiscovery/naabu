//go:build linux || darwin || windows

package scan

import (
	"net"
	"testing"
	"time"

	"github.com/Mzack9999/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// These tests drive the receive path that turns a reply into a recorded port.
// isDecoySynAck is covered on its own elsewhere; what matters here is the order
// of the guards around it - a decoy that is rejected by the predicate but still
// reaches TcpChan would be indistinguishable from no fix at all.

const testResponderIP = "203.0.113.10"

// registerTestHandler installs a listen handler in the global registry and
// removes it when the test ends. Registry mutation makes these tests unsafe to
// run in parallel with each other.
func registerTestHandler(t *testing.T, localPort int, phase State) *ListenHandler {
	t.Helper()

	handler := NewListenHandler()
	handler.Port = localPort
	handler.Phase.Set(phase)
	handler.TcpChan = make(chan *PkgResult, 1)
	handler.UdpChan = make(chan *PkgResult, 1)
	handler.HostDiscoveryChan = make(chan *PkgResult, 1)

	listenHandlersMu.Lock()
	ListenHandlers = append(ListenHandlers, handler)
	listenHandlersMu.Unlock()

	t.Cleanup(func() {
		listenHandlersMu.Lock()
		defer listenHandlersMu.Unlock()
		for index, existing := range ListenHandlers {
			if existing == handler {
				ListenHandlers = append(ListenHandlers[:index], ListenHandlers[index+1:]...)
				break
			}
		}
	})

	return handler
}

// synAckFrom builds a SYN-ACK carrying the cookie naabu expects for a probe it
// sent from localPort to responderPort, which is what an on-path forger echoes
// back: it does not need the cookie key, only the sequence number it just saw.
func synAckFrom(responderPort, localPort int, window uint16, options []layers.TCPOption) layers.TCP {
	dataOffset := uint8(5)
	if len(options) > 0 {
		dataOffset = 6
	}
	return layers.TCP{
		SrcPort:    layers.TCPPort(responderPort),
		DstPort:    layers.TCPPort(localPort),
		SYN:        true,
		ACK:        true,
		Window:     window,
		DataOffset: dataOffset,
		Options:    options,
		Ack:        SynCookie(net.ParseIP(testResponderIP), uint16(responderPort), uint16(localPort)) + 1,
	}
}

func received(t *testing.T, results chan *PkgResult) *PkgResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func TestTransportReaderRejectsDecoySynAck(t *testing.T) {
	const (
		localPort     = 31337
		responderPort = 8080
	)

	mss := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4},
	}

	cases := []struct {
		name       string
		tcp        layers.TCP
		wantIsOpen bool
		why        string
	}{
		{
			name:       "genuine syn-ack is recorded",
			tcp:        synAckFrom(responderPort, localPort, 65535, []layers.TCPOption{mss}),
			wantIsOpen: true,
			why:        "a real stack advertises a window and an MSS",
		},
		{
			name:       "cookie-valid decoy is dropped",
			tcp:        synAckFrom(responderPort, localPort, 0, nil),
			wantIsOpen: false,
			why:        "an on-path forger echoes a valid cookie, so only the fingerprint separates it",
		},
		{
			name: "wrong cookie is dropped before the decoy check",
			tcp: func() layers.TCP {
				tcp := synAckFrom(responderPort, localPort, 65535, []layers.TCPOption{mss})
				tcp.Ack++
				return tcp
			}(),
			wantIsOpen: false,
			why:        "a reply that acknowledges a SYN we never sent is not ours",
		},
		{
			name:       "reply for another handler's port is ignored",
			tcp:        synAckFrom(responderPort, localPort+1, 65535, []layers.TCPOption{mss}),
			wantIsOpen: false,
			why:        "handlers must not steal each other's replies",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := registerTestHandler(t, localPort, Scan)

			transportReaderCallback(tc.tcp, layers.UDP{}, testResponderIP, "")

			result := received(t, handler.TcpChan)
			if !tc.wantIsOpen {
				require.Nil(t, result, tc.why)
				return
			}
			require.NotNil(t, result, tc.why)
			require.Equal(t, responderPort, result.port.Port)
			require.Equal(t, testResponderIP, result.ipv4)
		})
	}
}

// TestTransportReaderHostDiscoveryIgnoresDecoy pins a deliberate asymmetry: the
// host discovery phase records the responder before the SYN-ACK is inspected,
// so a forged reply still marks the host alive. That is intended - a middlebox
// answering for the address proves something is reachable there - but it means
// the decoy filter protects port results only.
func TestTransportReaderHostDiscoveryIgnoresDecoy(t *testing.T) {
	const (
		localPort     = 31338
		responderPort = 8080
	)

	handler := registerTestHandler(t, localPort, HostDiscovery)

	transportReaderCallback(synAckFrom(responderPort, localPort, 0, nil), layers.UDP{}, testResponderIP, "")

	require.NotNil(t, received(t, handler.HostDiscoveryChan),
		"host discovery treats any reply as proof of life")
	require.Nil(t, received(t, handler.TcpChan),
		"no port may be recorded during host discovery")
}
