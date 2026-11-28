//go:build !windows

package scan

func isPlatformRefused(error) bool {
	return false
}
