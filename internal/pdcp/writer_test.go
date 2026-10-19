package pdcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	unitutils "github.com/projectdiscovery/utils/unit"
	"github.com/stretchr/testify/require"
)

func TestUploadWriterKeepsResultAtChunkBoundary(t *testing.T) {
	var (
		mu       sync.Mutex
		uploaded int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		uploaded += bytes.Count(body, []byte("\n"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"asset_id":"abcdefghij0123456789"}`))
	}))
	defer server.Close()

	writer, err := NewUploadWriterCallback(context.Background(), &pdcpauth.PDCPCredentials{APIKey: "test", Server: server.URL})
	require.NoError(t, err)

	// results of about 1 MB each, so the fourth one doesn't fit into the
	// current chunk and starts a new one
	banner := strings.Repeat("a", unitutils.Mega)
	const total = 6
	callback := writer.GetWriterCallback()
	for i := 0; i < total; i++ {
		callback(&result.HostResult{IP: "192.0.2.1", Ports: []*port.Port{{Port: 80 + i, Protocol: protocol.TCP, Service: &port.Service{Banner: banner}}}})
	}
	writer.Close()

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, total, uploaded)
}
