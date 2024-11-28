package scan

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPingHosts(t *testing.T) {
	if os.Getuid() == 0 {
		tests := []struct {
			args    string
			want    bool
			wantErr bool
		}{
			{"127.0.0.1", true, false},
			{"localhost", true, false},
			{"aaaaa", false, true},
		}

		for _, tt := range tests {
			t.Run(tt.args, func(t *testing.T) {
				pingResults, err := PingHosts([]string{tt.args})
				if tt.wantErr {
					assert.NotNil(t, err)
				} else {
					assert.Nil(t, err)
				}
				if tt.want {
					assert.NotEmpty(t, pingResults)
					fastest, err := pingResults.GetFastestHost()
					assert.Nil(t, err)
					assert.NotEmpty(t, pingResults.Hosts)
					assert.NotEmpty(t, fastest.Host)
				} else {
					assert.Empty(t, pingResults)
				}
			})
		}
	}
}
