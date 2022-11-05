package scan

import (
	"net"

	"github.com/pkg/errors"
	iputil "github.com/projectdiscovery/utils/ip"
)

// CdnCheck verifies if the given ip is part of Cdn ranges
func (s *Scanner) CdnCheck(ip string) (bool, string, error) {
	if s.cdn == nil {
		return false, "", errors.New("cdn client not initialized")
	}
	if !iputil.IsIP(ip) {
		return false, "", errors.Errorf("%s is not a valid ip", ip)
	}
	return s.cdn.Check(net.ParseIP((ip)))
}
