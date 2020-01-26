package scan

import (
	"fmt"
	"net"

	"github.com/projectdiscovery/naabu/pkg/log"
)

// ConnectVerify is used to verify if ports are accurate using a connect request
func (s *Scanner) ConnectVerify(host string, ports map[int]struct{}) map[int]struct{} {
	for port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), s.timeout)
		if err != nil {
			delete(ports, port)
			continue
		}
		log.Debugf("Validated active port %d on %s\n", port, s.host.String())
		conn.Close()
	}
	return ports
}
