//go:build windows

package scan

func init() {
	ArpRequestAsync = func(ip string) {}
}
