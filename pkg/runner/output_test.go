package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestCSVHeadersHaveNoEmptyColumns(t *testing.T) {
	headers = []string{}

	result := &Result{}
	got, err := result.CSVHeaders(nil)
	assert.NoError(t, err)
	assert.NotContains(t, got, "")
	assert.Contains(t, got, "name")
	assert.Contains(t, got, "product")
	assert.Contains(t, got, "version")
	assert.Contains(t, got, "extra_info")
}

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

func TestWriteHostOutputWithService(t *testing.T) {
	host := "127.0.0.1"
	ports := []*port.Port{
		{
			Port:     80,
			Protocol: protocol.TCP,
			Service: &port.Service{
				Name:    "http",
				Product: "nginx",
				Version: "1.26.2",
			},
		},
	}
	var s string
	buf := bytes.NewBufferString(s)
	assert.Nil(t, WriteHostOutput(host, ports, false, "", buf))
	t.Log(buf.String())
	assert.Contains(t, buf.String(), "127.0.0.1:80 [http nginx 1.26.2]")
}

func TestFormatHostPortOutput(t *testing.T) {
	portWithService := &port.Port{
		Port:     443,
		Protocol: protocol.TCP,
		Service: &port.Service{
			Name:    "https",
			Product: "https",
			Version: "1.1",
		},
	}

	formatted := formatOutput("example.com", portWithService, true, "cloudflare")
	assert.Equal(t, "example.com:443 [cloudflare] [https 1.1]", formatted)
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
	assert.Nil(t, WriteJSONOutput(host, ip, ports, true, false, "", nil, buf))
	assert.Equal(t, 3, len(strings.Split(buf.String(), "\n")))
}
