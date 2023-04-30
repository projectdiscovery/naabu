package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestWriteHostOutput(t *testing.T) {
	host := "127.0.0.1"
	ports := []*port.Port{
		{Port: 80, Protocol: protocol.TCP},
		{Port: 8080, Protocol: protocol.TCP},
	}
	var s string
	buf := bytes.NewBufferString(s)
	assert.Nil(t, WriteHostOutput(host, ports, false, "", buf))
	assert.Contains(t, buf.String(), "127.0.0.1:80")
	assert.Contains(t, buf.String(), "127.0.0.1:8080")
}

func TestWriteJSONOutput(t *testing.T) {
	host := "localhost"
	ip := "127.0.0.1"
	ports := []*port.Port{
		{Port: 80, Protocol: protocol.TCP},
		{Port: 8080, Protocol: protocol.TCP},
	}
	var s string
	buf := bytes.NewBufferString(s)
	assert.Nil(t, WriteJSONOutput(host, ip, ports, true, false, "", buf))
	assert.Equal(t, 3, len(strings.Split(buf.String(), "\n")))
}
