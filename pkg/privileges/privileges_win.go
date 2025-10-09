//go:build windows

package privileges

// IsPrivileged on windows doesn't matter as we are using connect scan
func isPrivileged() bool {
	return false
}
