package scan

import (
	"fmt"
	"net"
)

// CdnCheck verifies if the given ip is part of Cdn ranges
func (s *Scanner) CdnCheck(ip string) (bool, error) {
	if s.cdn == nil {
		return false, fmt.Errorf("cdn client not initialized")
	}
	return s.cdn.Check(net.ParseIP((ip)))
}
