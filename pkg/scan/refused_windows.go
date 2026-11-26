//go:build windows

package scan

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isPlatformRefused matches the Winsock code a dial returns, which differs
// from the invented syscall.ECONNREFUSED value on Windows.
func isPlatformRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
