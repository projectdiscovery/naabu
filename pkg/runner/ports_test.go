package runner

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestParsePortsList(t *testing.T) {
	tests := []struct {
		args    string
		want    []*port.Port
		wantErr bool
	}{
		{"1,2,3,4", []*port.Port{{Port: 1, Protocol: protocol.TCP}, {Port: 2, Protocol: protocol.TCP}, {Port: 3, Protocol: protocol.TCP}, {Port: 4, Protocol: protocol.TCP}}, false},
		{"1-3,10", []*port.Port{{Port: 1, Protocol: protocol.TCP}, {Port: 2, Protocol: protocol.TCP}, {Port: 3, Protocol: protocol.TCP}, {Port: 10, Protocol: protocol.TCP}}, false},
		{"17,17,17,18", []*port.Port{{Port: 17, Protocol: protocol.TCP}, {Port: 18, Protocol: protocol.TCP}}, false},
		{"a", nil, true},
		{"0", nil, true},
		{"0-100", nil, true},
		{"0-65535", nil, true},
		{"1-65535", func() []*port.Port {
			ports := make([]*port.Port, 0, 65535)
			for i := 1; i <= 65535; i++ {
				ports = append(ports, &port.Port{Port: i, Protocol: protocol.TCP})
			}
			return ports
		}(), false},
		{"80,443", []*port.Port{{Port: 80, Protocol: protocol.TCP}, {Port: 443, Protocol: protocol.TCP}}, false},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got, err := parsePortsList(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePortsList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePortsList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExcludePorts(t *testing.T) {
	var options Options
	ports := []*port.Port{
		{Port: 1, Protocol: protocol.TCP},
		{Port: 10, Protocol: protocol.TCP},
	}

	// no filtering
	filteredPorts, err := excludePorts(&options, ports)
	assert.Nil(t, err)
	assert.EqualValues(t, filteredPorts, ports)

	// invalid filter
	options.ExcludePorts = goflags.StringSlice{"a"}
	_, err = excludePorts(&options, ports)
	assert.NotNil(t, err)

	// valid filter
	options.ExcludePorts = goflags.StringSlice{"1"}
	filteredPorts, err = excludePorts(&options, ports)
	assert.Nil(t, err)
	expectedPorts := []*port.Port{
		{Port: 10, Protocol: protocol.TCP},
	}
	assert.EqualValues(t, expectedPorts, filteredPorts)
}

func TestParsePorts(t *testing.T) {
	// top ports
	tests := []struct {
		args    string
		want    int
		wantErr bool
	}{
		{"full", 65535, false},
		{"100", 100, false},
		{"1000", 1000, false},
		{"a", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			var options Options
			options.TopPorts = tt.args
			got, err := ParsePorts(&options)
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tt.want, len(got))
		})
	}

	// ports
	tests = []struct {
		args    string
		want    int
		wantErr bool
	}{
		{"-", 65535, false},
		{"a", 0, true},
		{"1,2,4-10", 9, false},
		{"0", 0, true},
		{"0-100", 0, true},
		{"1-65535", 65535, false},
		{"80,443", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			var options Options
			options.Ports = tt.args
			got, err := ParsePorts(&options)
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tt.want, len(got))
		})
	}

	// default to 100 ports
	got, err := ParsePorts(&Options{})
	assert.Nil(t, err)
	assert.Equal(t, 100, len(got))
}
