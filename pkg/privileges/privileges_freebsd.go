//go:build freebsd

package privileges

import (
	"os"
)

// isPrivileged checks if the current process is root
func isPrivileged() bool {
	return os.Geteuid() == 0
}
