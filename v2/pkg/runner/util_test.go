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
		wantErr bool
	}{
		{"10.10.10.10", []string{"10.10.10.10"}, false},
		{"localhost", []string{"127.0.0.1"}, false},
		{"aaaa", nil, true},
		{"10.10.10.0/24", nil, true},
	}

	var r Runner
	if dnsclient, err := dnsx.New(dnsx.DefaultOptions); err != nil {
		assert.Error(t, err)
	} else {
		r.dnsclient = dnsclient
	}

	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			var options Options
			options.TopPorts = tt.args
			got, err := r.host2ips(tt.args)
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
