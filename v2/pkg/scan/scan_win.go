//go:build windows

package scan

func init() {
	TransportReadWorkerPCAP = func(s *Scanner) {}
}
