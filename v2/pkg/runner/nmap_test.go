package runner

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestHandleNmap(t *testing.T) {
	// just attempt to start nmap
	var r Runner
	r.options = &Options{}
	// nmap with empty cli shouldn't trigger any error
	res := result.NewResult()
	r.scanner = &scan.Scanner{}
	r.scanner.ScanResults = res
	assert.Nil(t, r.handleNmap())
	r.scanner.ScanResults.IPPorts = make(map[string]map[int]struct{})
	// nmap syntax error (this test might fail if nmap is not installed on the box)
	assert.Nil(t, r.handleNmap())
	r.scanner.ScanResults.IPPorts = map[string]map[int]struct{}{"127.0.0.1": {8080: struct{}{}}}
	assert.Nil(t, r.handleNmap())
}
