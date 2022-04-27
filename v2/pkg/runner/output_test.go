package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteHostOutput(t *testing.T) {
	host := "127.0.0.1"
	ports := map[int]struct{}{80: {}, 8080: {}}
	var s string
	buf := bytes.NewBufferString(s)
	assert.Nil(t, WriteHostOutput(host, ports, buf))
	assert.Contains(t, buf.String(), "127.0.0.1:80")
	assert.Contains(t, buf.String(), "127.0.0.1:8080")
}

func TestWriteJSONOutput(t *testing.T) {
	host := "localhost"
	ip := "127.0.0.1"
	ports := map[int]struct{}{80: {}, 8080: {}}
	var s string
	buf := bytes.NewBufferString(s)
	assert.Nil(t, WriteJSONOutput(host, ip, ports, buf))
	assert.Equal(t, 3, len(strings.Split(buf.String(), "\n")))
}
