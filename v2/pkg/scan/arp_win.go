//go:build windows

package scan

func init() {
	ArpRequestAsync = func(s *Scanner, ip string) {}
}
