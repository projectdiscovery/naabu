package scan

import (
	"log"
	"net"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestConnectVerify(t *testing.T) {
	go func() {
		// start tcp server
		l, err := net.Listen("tcp", ":17895")
		if err != nil {
			assert.Nil(t, err)
		}
		defer func() {
			if err := l.Close(); err != nil {
				log.Printf("could not close listener: %s\n", err)
			}
		}()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer func() {
				_ = conn.Close()
			}()
		}
	}()

	s, err := NewScanner(&Options{})
	assert.Nil(t, err)
	wanted := []*port.Port{
		{Port: 17895, Protocol: protocol.TCP},
	}

	targetPorts := []*port.Port{
		{Port: 17895, Protocol: protocol.TCP},
		{Port: 17896, Protocol: protocol.TCP},
	}
	got := s.ConnectVerify("localhost", targetPorts)
	assert.EqualValues(t, wanted, got)
}
