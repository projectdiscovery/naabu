package scan

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

type PortProbe struct {
	Port *port.Port
	Data []byte
}

// DiscoverServices is used to verify if ports are accurate using a connect request
func (s *Scanner) DiscoverServices(host string, p *port.Port, timeout time.Duration) ([]PortProbe, error) {
	if timeout == 0 {
		return nil, errors.New("read timeout not defined")
	}

	var portProbes []PortProbe

	for _, probe := range probe.Probes {
		data, err := probe.Do(host, p, timeout)
		portProbe := PortProbe{
			Port: p,
			Data: data,
		}
		if err != nil && !errors.Is(err, io.EOF) {
			// todo: print failures for debug purposes
			log.Println(err)
			continue
		}
		portProbes = append(portProbes, portProbe)
	}

	if len(portProbes) == 0 {
		return nil, errors.New("no services found")
	}

	return portProbes, nil
}
