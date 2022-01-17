//go:build linux || darwin

package privileges

import (
	"os"

	"github.com/syndtr/gocapability/capability"
)

// isPrivileged checks if the current process has the CAP_NET_RAW capability or is root
func isPrivileged() bool {
	caps, err := capability.NewPid2(0)
	if err == nil {
		if err := caps.Load(); err == nil {
			return caps.Get(capability.EFFECTIVE, capability.CAP_NET_RAW)
		}
	}

	return os.Geteuid() == 0
}
