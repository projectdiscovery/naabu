package scan

import "net"

// CdnCheck verifies if the given ip is part of Cdn ranges
func (s *Scanner) CdnCheck(ip string) bool {
	ok, err := s.cdn.Check(net.ParseIP((ip)))

	return ok && err == nil
}
