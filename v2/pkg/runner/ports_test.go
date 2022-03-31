package runner

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePortsList(t *testing.T) {
	tests := []struct {
		args    string
		want    map[int]struct{}
		wantErr bool
	}{
		{"1,2,3,4", map[int]struct{}{1: {}, 2: {}, 3: {}, 4: {}}, false},
		{"1-3,10", map[int]struct{}{1: {}, 2: {}, 3: {}, 10: {}}, false},
		{"17,17,17,18", map[int]struct{}{17: {}, 18: {}}, false},
		{"a", nil, true},
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
	ports := map[int]struct{}{1: {}, 10: {}}

	// no filtering
	filteredPorts, err := excludePorts(&options, ports)
	assert.Nil(t, err)
	assert.EqualValues(t, filteredPorts, ports)

	// invalida filter
	options.ExcludePorts = "a"
	_, err = excludePorts(&options, ports)
	assert.NotNil(t, err)

	// valid filter
	options.ExcludePorts = "1"
	filteredPorts, err = excludePorts(&options, ports)
	assert.Nil(t, err)
	expectedPorts := map[int]struct{}{10: {}}
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
