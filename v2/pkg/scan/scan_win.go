//go:build windows

package scan

func init() {
	InitScanner = func(s *Scanner) error { return nil }
}
