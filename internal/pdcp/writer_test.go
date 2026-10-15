package pdcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/stretchr/testify/require"
)

func TestUploadWriterChunkBoundaryPreservesAllResults(t *testing.T) {
	origChunkSize := MaxChunkSize
	MaxChunkSize = 100 // Set small chunk size to force chunk boundary splitting
	t.Cleanup(func() {
		MaxChunkSize = origChunkSize
	})

	var mu sync.Mutex
	var receivedHosts []string
	var chunkCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		mu.Lock()
		defer mu.Unlock()
		chunkCount++

		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var hr result.HostResult
			if err := json.Unmarshal([]byte(line), &hr); err == nil {
				receivedHosts = append(receivedHosts, hr.Host)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(uploadResponse{
			ID:      "testassetid1234567890",
			Message: "success",
		})
	}))
	defer server.Close()

	creds := &pdcpauth.PDCPCredentials{
		Server: server.URL,
		APIKey: "dummy-key",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	writer, err := NewUploadWriterCallback(ctx, creds)
	require.NoError(t, err)
	require.NotNil(t, writer)

	cb := writer.GetWriterCallback()

	expectedHosts := []string{
		"host-1-test.local",
		"host-2-test.local",
		"host-3-test.local",
		"host-4-test.local",
		"host-5-test.local",
	}

	for _, host := range expectedHosts {
		cb(&result.HostResult{
			Host: host,
			IP:   "192.168.1.1",
		})
	}

	time.Sleep(50 * time.Millisecond)
	writer.Close()

	mu.Lock()
	defer mu.Unlock()

	require.GreaterOrEqual(t, chunkCount, 2, "expected multiple chunks to be uploaded across chunk boundaries")
	require.Equal(t, expectedHosts, receivedHosts, "all hosts must be received across chunk boundaries without dropping any")
	require.Equal(t, int32(len(expectedHosts)), writer.counter.Load(), "counter must match total sent results")
}
