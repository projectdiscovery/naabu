package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMillisecondDurationSet(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "200", want: 200 * time.Millisecond},
		{in: "1000", want: time.Second},
		{in: "3000000000", want: 3000000000 * time.Millisecond},
		{in: "200ms", want: 200 * time.Millisecond},
		{in: "2s", want: 2 * time.Second},
		{in: "1m", want: time.Minute},
		{in: "abc", wantErr: true},
		{in: "9223372036855", wantErr: true},
		{in: "99999999999999999999", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var d time.Duration
			v := newMillisecondDuration(&d, DefaultPortTimeoutSynScan)
			err := v.Set(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, d)
		})
	}
}

func TestGetTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  time.Duration
		scanType string
		want     time.Duration
	}{
		{name: "unset syn", timeout: 0, scanType: SynScan, want: DefaultPortTimeoutSynScan},
		{name: "unset connect", timeout: 0, scanType: ConnectScan, want: DefaultPortTimeoutConnectScan},
		{name: "legacy sdk millisecond count", timeout: 1000, scanType: ConnectScan, want: DefaultPortTimeoutConnectScan},
		{name: "explicit sub-500ms honored", timeout: 200 * time.Millisecond, scanType: ConnectScan, want: 200 * time.Millisecond},
		{name: "explicit seconds honored", timeout: 2 * time.Second, scanType: SynScan, want: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{Timeout: tt.timeout, ScanType: tt.scanType}
			require.Equal(t, tt.want, o.GetTimeout())
		})
	}
}
