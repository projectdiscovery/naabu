//go:build linux || unix

package privileges

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// isPrivileged checks if the current process has the CAP_NET_RAW capability or is root
func isPrivileged() bool {
	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     int32(os.Getpid()),
	}
	data := unix.CapUserData{}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.Capget(&header, &data); err == nil {
		data.Inheritable = (1 << unix.CAP_NET_RAW)

		if err := unix.Capset(&header, &data); err == nil {
			return true
		}
	}
	return os.Geteuid() == 0
}
