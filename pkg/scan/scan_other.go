//go:build !linux && !darwin && !windows

package scan

// BuildBPFFilter returns empty BPF filter on platforms without pcap support.
func BuildBPFFilter() string {
	return ""
}

// UpdateBPFFilter is a no-op on platforms without pcap support.
func UpdateBPFFilter() error {
	return nil
}
