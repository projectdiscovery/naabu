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

	matched, val, err := s.cdn.CheckWAF(net.ParseIP((ip)))
	if err != nil {
		return false, "", err
	}

	if matched {
		return matched, val, err
	}

	return s.cdn.CheckCDN(net.ParseIP((ip)))
}
