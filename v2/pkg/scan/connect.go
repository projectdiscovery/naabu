package scan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/port/probe"
)

// ConnectVerify is used to verify if ports are accurate using a connect request
func (s *Scanner) ConnectVerify(host string, ports []*port.Port) []*port.Port {
	var verifiedPorts []*port.Port
	for _, p := range ports {
		conn, err := net.DialTimeout(p.Protocol.String(), fmt.Sprintf("%s:%d", host, p.Port), s.timeout)
		if err != nil {
			continue
		}
		gologger.Debug().Msgf("Validated active port %d on %s\n", p.Port, host)
		conn.Close()
		verifiedPorts = append(verifiedPorts, p)
	}
	return verifiedPorts
}

// DiscoverServices is used to verify if ports are accurate using a connect request
func (s *Scanner) DiscoverServices(host string, p *port.Port, timeout time.Duration) ([]port.PortProbe, error) {
	if timeout == 0 {
		return nil, errors.New("read timeout not defined")
	}

	var portProbes []port.PortProbe

	for _, probe := range probe.Probes {
		if !probe.ValidFor(p) {
			continue
		}
		data, err := probe.Do(host, p, timeout)
		if err != nil && !errors.Is(err, io.EOF) {
			continue
		}
		portProbe := port.PortProbe{
			Port:    p,
			Data:    data,
			ProbeId: reflect.TypeOf(probe).Name(),
		}
		portProbes = append(portProbes, portProbe)
	}

	if len(portProbes) == 0 {
		return nil, errors.New("no services found")
	}

	return portProbes, nil
}
