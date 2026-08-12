package runner

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/stretchr/testify/require"
)

func TestDecoySynAckCallbackIsExposedToRunnerConsumers(t *testing.T) {
	var got *result.HostResult
	r, err := NewRunner(&Options{
		Host:     []string{"127.0.0.1"},
		Ports:    "80",
		ScanType: scan.TypeConnect,
		OnDecoySynAck: func(hr *result.HostResult) {
			got = hr
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.Close()) })

	require.NotNil(t, r.scanner.ListenHandler.OnDecoySynAck)
	r.scanner.ListenHandler.OnDecoySynAck("127.0.0.1", 80)

	require.NotNil(t, got)
	require.Equal(t, "127.0.0.1", got.Host)
	require.Equal(t, "127.0.0.1", got.IP)
	require.Len(t, got.Ports, 1)
	require.Equal(t, 80, got.Ports[0].Port)
}
