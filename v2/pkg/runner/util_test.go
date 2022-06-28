package runner

import (
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/stretchr/testify/assert"
)

func Test_host2ips(t *testing.T) {
	tests := []struct {
		args    string
		want    []string
		wantV6  []string
		wantErr bool
	}{
		{"10.10.10.10", []string{"10.10.10.10"}, nil, false},
		{"localhost", []string{"127.0.0.1"}, []string{"::1"}, false},
		{"aaaa", nil, nil, true},
		{"10.10.10.0/24", nil, nil, true},
	}

	r, err := NewRunner(&Options{IPVersion: []string{"4", "6"}})
	assert.Nil(t, err)
	if dnsclient, err := dnsx.New(dnsx.DefaultOptions); err != nil {
		assert.Error(t, err)
	} else {
		r.dnsclient = dnsclient
	}

	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			var options Options
			options.TopPorts = tt.args
			got, gotV6, err := r.host2ips(tt.args)
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantV6, gotV6)

		})
	}
}
