package scan

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSynCookieRoundTrip(t *testing.T) {
	ip := net.ParseIP("93.184.216.34")
	const targetPort, ourPort = 443, 54321

	seq := SynCookie(ip, targetPort, ourPort)
	// A real SYN-ACK acknowledges seq with seq+1.
	require.True(t, verifySynCookie(ip.String(), "", targetPort, ourPort, seq+1),
		"valid SYN-ACK must pass cookie verification")
}

func TestSynCookieRejectsForgery(t *testing.T) {
	ip := net.ParseIP("93.184.216.34")
	const targetPort, ourPort = 443, 54321
	seq := SynCookie(ip, targetPort, ourPort)

	// Wrong ack value.
	require.False(t, verifySynCookie(ip.String(), "", targetPort, ourPort, seq+2))
	// Right ack but wrong responder IP.
	require.False(t, verifySynCookie("8.8.8.8", "", targetPort, ourPort, seq+1))
	// Right ack but wrong port.
	require.False(t, verifySynCookie(ip.String(), "", 80, ourPort, seq+1))
	// Unparseable source address.
	require.False(t, verifySynCookie("", "", targetPort, ourPort, seq+1))
}

func TestSynCookie4MatchesSynCookie(t *testing.T) {
	ip4 := [4]byte{93, 184, 216, 34}
	ip := net.IPv4(93, 184, 216, 34)
	const targetPort, ourPort = 8080, 40000
	require.Equal(t, SynCookie(ip, targetPort, ourPort), SynCookie4(ip4, targetPort, ourPort),
		"fast IPv4 cookie must equal the generic cookie")
}

func TestSynCookieWrapAround(t *testing.T) {
	// Force a cookie of 0xFFFFFFFF to exercise uint32 ack-1 wraparound:
	// ack = seq+1 = 0, ack-1 must wrap back to 0xFFFFFFFF.
	ip := net.ParseIP("10.0.0.1")
	for p := uint16(1); p != 0; p++ {
		if SynCookie(ip, p, 12345) == 0xFFFFFFFF {
			require.True(t, verifySynCookie(ip.String(), "", p, 12345, 0))
			return
		}
	}
	t.Skip("no cookie hit 0xFFFFFFFF in search space")
}
