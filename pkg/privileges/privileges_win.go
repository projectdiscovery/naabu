//go:build windows

package privileges

import (
	"golang.org/x/sys/windows"
)

// isPrivileged reports whether the process token is elevated. On Windows SYN
// scans need an elevated admin token for Npcap inject/capture; membership in
// the Administrators group alone is not enough under UAC.
func isPrivileged() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
