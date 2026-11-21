package scan

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsLocalExhaustion(t *testing.T) {
	dialErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	require.True(t, isLocalExhaustion(dialErr(syscall.EADDRNOTAVAIL)), "source ports exhausted")
	require.True(t, isLocalExhaustion(dialErr(syscall.EMFILE)), "open file limit reached")
	require.False(t, isLocalExhaustion(dialErr(syscall.ECONNREFUSED)), "a closed port is not local loss")
	require.False(t, isLocalExhaustion(nil))
}

func TestCountLocalFailure(t *testing.T) {
	s := &Scanner{}
	s.countLocalFailure(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)})
	s.countLocalFailure(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	s.countLocalFailure(nil)
	require.EqualValues(t, 1, s.LocalDialFailures.Load(), "only local exhaustion counts")
}
