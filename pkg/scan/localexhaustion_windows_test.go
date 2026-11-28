//go:build windows

package scan

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestIsLocalExhaustionWinsock(t *testing.T) {
	dialErr := func(errno error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", errno)}
	}
	require.True(t, isLocalExhaustion(dialErr(windows.WSAEADDRNOTAVAIL)), "source ports exhausted")
	require.True(t, isLocalExhaustion(dialErr(windows.WSAEMFILE)), "too many open sockets")
	require.True(t, isLocalExhaustion(dialErr(windows.WSAENOBUFS)), "no buffer space")
	require.False(t, isLocalExhaustion(dialErr(windows.WSAECONNREFUSED)), "a closed port is not local loss")
}
