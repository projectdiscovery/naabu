//go:build linux || unix

package privileges

import (
	"os"

	"golang.org/x/sys/unix"
)

// isPrivileged reports whether the current process can perform raw-socket
// operations, either because it holds CAP_NET_RAW (Effective) or because it
// runs as root. The capability check is read-only.
func isPrivileged() bool {
	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
	}
	// LINUX_CAPABILITY_VERSION_3 returns two 32-bit words (low + high) per
	// set, so the kernel writes into a [2]CapUserData. Passing a single
	// struct would under-size the buffer by 12 bytes.
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err == nil {
		return (data[0].Effective & (1 << unix.CAP_NET_RAW)) != 0
	}
	return os.Geteuid() == 0
}
