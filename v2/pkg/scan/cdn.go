package scan

import (
	"net"

	"github.com/pkg/errors"
)

// CdnCheck verifies if the given ip is part of Cdn ranges
func (s *Scanner) CdnCheck(ip string) (bool, string, error) {
	if s.cdn == nil {
		return false, "", errors.New("cdn client not initialized")
	}
	return s.cdn.Check(net.ParseIP((ip)))
}
