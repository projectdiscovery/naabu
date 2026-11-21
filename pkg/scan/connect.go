package scan

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

// ConnectVerify is used to verify if ports are accurate using a connect request
func (s *Scanner) ConnectVerify(host string, ports []*port.Port) []*port.Port {
	var verifiedPorts []*port.Port
	for _, p := range ports {
		target := net.JoinHostPort(host, fmt.Sprint(p.Port))
		conn, err := net.DialTimeout(p.Protocol.String(), target, s.timeout)
		if err != nil {
			s.countLocalFailure(err)
			continue
		}
		gologger.Debug().Msgf("Validated active port %d on %s\n", p.Port, host)
		_ = conn.Close()
		verifiedPorts = append(verifiedPorts, p)
	}
	return verifiedPorts
}

// isLocalExhaustion reports whether a dial failed because this machine ran
// out of sockets or source ports, not because the target port is closed.
func isLocalExhaustion(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOBUFS)
}

func (s *Scanner) countLocalFailure(err error) {
	if isLocalExhaustion(err) {
		s.LocalDialFailures.Add(1)
	}
}
