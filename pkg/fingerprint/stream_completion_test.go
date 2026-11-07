package fingerprint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintStreamEmitsUnmatchedEndpoint(t *testing.T) {
	// Given a target and an empty database, so no network probes are needed.
	targets := make(chan Target, 1)
	targets <- Target{IP: "192.0.2.1", Port: 80}
	close(targets)
	engine := New(nil, WithWorkers(1))

	// When fingerprinting completes without a match.
	var got []StreamResult
	for sr := range engine.FingerprintStream(context.Background(), targets) {
		got = append(got, sr)
	}

	// Then completion is observable even though the service is unknown.
	require.Len(t, got, 1)
	require.Equal(t, "192.0.2.1", got[0].IP)
	require.Equal(t, 80, got[0].Port)
	require.Nil(t, got[0].Service)
}
