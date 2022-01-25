//go:build darwin

package privileges

import (
	"os"
)

// isPrivileged checks if the current process has the CAP_NET_RAW capability or is root
func isPrivileged() bool {
	return os.Geteuid() == 0
}
