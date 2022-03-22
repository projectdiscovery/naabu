package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCdnCheck(t *testing.T) {
	s, err := NewScanner(&Options{ExcludeCdn: true})
	assert.Nil(t, err)
	tests := []struct {
		args    string
		want    bool
		wantErr bool
	}{
		{"192.168.1.1", false, false},
		{"10.10.10.10", false, false},
		{"aaaaa", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.args, func(t *testing.T) {
			isCdn, _, err := s.CdnCheck(tt.args)
			if tt.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tt.want, isCdn)
		})
	}
}
