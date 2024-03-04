package runner

import (
	"testing"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
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
		{"localhost", []string{"127.0.0.1"}, []string{"::1"}, false}, // some linux distribution don't have ::1 in /etc/hosts
		{"aaaa", nil, nil, true},
		{"10.10.10.0/24", nil, nil, true},
	}

	r, err := NewRunner(&Options{IPVersion: []string{scan.IPv4, scan.IPv6}, Retries: 1})
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
			// As some distributions don't handle correctly ipv6 we compare results only if necessary
			if len(gotV6) > 0 && len(tt.wantV6) > 0 {
				assert.Equal(t, tt.wantV6, gotV6)
			}
		})
	}
}
