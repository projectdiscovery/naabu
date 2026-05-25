//go:build linux || unix

package privileges

import (
	"os"
	"runtime"

	"github.com/projectdiscovery/naabu/v2/pkg/israce"
	"golang.org/x/sys/unix"
)

// isPrivileged checks if the current process has the CAP_NET_RAW capability or is root
func isPrivileged() bool {
	// runtime.LockOSThread interferes with race detection
	if !israce.Enabled {
		header := unix.CapUserHeader{
			Version: unix.LINUX_CAPABILITY_VERSION_3,
			Pid:     int32(os.Getpid()),
		}
		data := unix.CapUserData{}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := unix.Capget(&header, &data); err == nil {
			return (data.Effective & (1 << unix.CAP_NET_RAW)) != 0
		}
	}
	return os.Geteuid() == 0
}
