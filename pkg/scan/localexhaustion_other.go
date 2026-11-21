//go:build !windows

package scan

// isPlatformExhaustion has no extra codes outside Windows, where the errno
// values of syscall are the ones a failed dial returns.
func isPlatformExhaustion(error) bool {
	return false
}
