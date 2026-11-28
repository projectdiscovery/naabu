//go:build windows

package scan

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isPlatformExhaustion reports the Winsock codes of a local socket shortage.
// Windows returns these from a failed dial, not the invented values that
// syscall.EADDRNOTAVAIL and its siblings hold there.
func isPlatformExhaustion(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL) || errors.Is(err, windows.WSAEMFILE) ||
		errors.Is(err, windows.WSAENOBUFS)
}
