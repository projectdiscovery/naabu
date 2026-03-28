package runner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Nil(t, WriteJSONOutput(host, ip, ports, true, false, "", nil, buf))
	assert.Equal(t, 3, len(strings.Split(buf.String(), "\n")))
}

func TestCopyServiceFieldsWithService(t *testing.T) {
	svc := &port.Service{
		Name:      "ssh",
		Product:   "OpenSSH",
		Version:   "8.9",
		ExtraInfo: "protocol 2.0",
		OSType:    "Linux",
		ServiceFP: "SSH-2.0-OpenSSH_8.9",
		Method:    "probe",
		CPEs:      []string{"cpe:/a:openbsd:openssh:8.9"},
	}

	result := &Result{}
	copyServiceFields(result, svc)

	assert.Equal(t, "ssh", result.Name)
	assert.Equal(t, "OpenSSH", result.Product)
	assert.Equal(t, "8.9", result.Version)
	assert.Equal(t, "protocol 2.0", result.ExtraInfo)
	assert.Equal(t, "Linux", result.OSType)
	assert.Equal(t, "SSH-2.0-OpenSSH_8.9", result.ServiceFP)
	assert.Equal(t, "probe", result.Method)
	assert.Equal(t, []string{"cpe:/a:openbsd:openssh:8.9"}, result.CPEs)
}

func TestCopyServiceFieldsNilService(t *testing.T) {
	result := &Result{
		Name:    "leftover",
		Product: "leftover",
		CPEs:    []string{"leftover"},
	}
	copyServiceFields(result, nil)

	assert.Empty(t, result.Name, "should clear Name when service is nil")
	assert.Empty(t, result.Product, "should clear Product when service is nil")
	assert.Nil(t, result.CPEs, "should clear CPEs when service is nil")
}

func TestCopyServiceFieldsEmptyService(t *testing.T) {
	result := &Result{Name: "old"}
	copyServiceFields(result, &port.Service{})

	assert.Empty(t, result.Name)
	assert.Empty(t, result.Product)
	assert.Nil(t, result.CPEs)
}

func TestCopyServiceFieldsCPEsMultiple(t *testing.T) {
	svc := &port.Service{
		Name: "mysql",
		CPEs: []string{"cpe:/a:oracle:mysql:8.0", "cpe:/a:mysql:mysql:8.0"},
	}

	result := &Result{}
	copyServiceFields(result, svc)
	assert.Equal(t, 2, len(result.CPEs))
}

func TestWriteJSONOutputWithServiceInfo(t *testing.T) {
	host := "example.com"
	ip := "93.184.216.34"
	ports := []*port.Port{
		{
			Port:     22,
			Protocol: protocol.TCP,
			Service: &port.Service{
				Name:      "ssh",
				Product:   "OpenSSH",
				Version:   "8.9",
				Method:    "probe",
				ServiceFP: "SSH-2.0-OpenSSH_8.9",
				CPEs:      []string{"cpe:/a:openbsd:openssh:8.9"},
			},
		},
	}

	var buf bytes.Buffer
	err := WriteJSONOutput(host, ip, ports, false, false, "", nil, &buf)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "ssh", parsed["name"])
	assert.Equal(t, "OpenSSH", parsed["product"])
	assert.Equal(t, "8.9", parsed["version"])
	assert.Equal(t, "probe", parsed["method"])
	assert.Equal(t, "SSH-2.0-OpenSSH_8.9", parsed["service_fp"])

	cpesRaw, ok := parsed["cpes"]
	require.True(t, ok, "JSON output should include cpes field")
	cpes := cpesRaw.([]interface{})
	assert.Len(t, cpes, 1)
	assert.Equal(t, "cpe:/a:openbsd:openssh:8.9", cpes[0])
}

func TestWriteJSONOutputWithoutService(t *testing.T) {
	host := "example.com"
	ip := "93.184.216.34"
	ports := []*port.Port{
		{Port: 80, Protocol: protocol.TCP},
	}

	var buf bytes.Buffer
	err := WriteJSONOutput(host, ip, ports, false, false, "", nil, &buf)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	_, hasName := parsed["name"]
	assert.False(t, hasName, "name should be omitted when no service")
	_, hasCPEs := parsed["cpes"]
	assert.False(t, hasCPEs, "cpes should be omitted when no service")
}

func TestResultJSONIncludesCPEs(t *testing.T) {
	r := &Result{
		IP:       "127.0.0.1",
		Port:     22,
		Protocol: "tcp",
		Name:     "ssh",
		Product:  "OpenSSH",
		Version:  "8.9",
		CPEs:     []string{"cpe:/a:openbsd:openssh:8.9"},
	}

	b, err := r.JSON(nil)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(b, &parsed)
	require.NoError(t, err)

	cpesRaw, ok := parsed["cpes"]
	require.True(t, ok, "JSON should contain cpes")
	cpes := cpesRaw.([]interface{})
	assert.Len(t, cpes, 1)
	assert.Equal(t, "cpe:/a:openbsd:openssh:8.9", cpes[0])
}

func TestResultJSONOmitsCPEsWhenEmpty(t *testing.T) {
	r := &Result{
		IP:       "127.0.0.1",
		Port:     80,
		Protocol: "tcp",
	}

	b, err := r.JSON(nil)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(b, &parsed)
	require.NoError(t, err)

	_, hasCPEs := parsed["cpes"]
	assert.False(t, hasCPEs, "cpes should be omitted when empty")
}
