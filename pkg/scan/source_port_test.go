package scan

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_SetSourcePort(t *testing.T) {
	origHandlers := ListenHandlers
	defer func() {
		ListenHandlers = origHandlers
	}()

	listenHandler := &ListenHandler{Port: 1111, Busy: false}
	ListenHandlers = []*ListenHandler{listenHandler}

	scanner := &Scanner{
		ListenHandler: listenHandler,
		ScanType:      TypeSyn,
	}

	// Valid port
	err := scanner.SetSourcePort("58915")
	require.NoError(t, err)
	assert.Equal(t, 58915, scanner.ListenHandler.Port)

	bpf := BuildBPFFilter()
	if bpf != "" {
		assert.Contains(t, bpf, "tcp")
	}

	// Invalid ports
	invalidPorts := []string{"0", "-1", "65536", "abc", "70000"}
	for _, portStr := range invalidPorts {
		err := scanner.SetSourcePort(portStr)
		assert.Error(t, err, "expected error for port %s", portStr)
	}
}

func TestNewScanner_WithSourcePort(t *testing.T) {
	origRouter := PkgRouter
	origPriv := privileges.IsPrivileged
	origHandlers := ListenHandlers
	defer func() {
		PkgRouter = origRouter
		privileges.IsPrivileged = origPriv
		ListenHandlers = origHandlers
	}()

	PkgRouter = &stubRouter{}
	privileges.IsPrivileged = true
	handler := &ListenHandler{Port: 2222, Busy: false}
	ListenHandlers = []*ListenHandler{handler}

	opts := &Options{
		ScanType:   TypeSyn,
		SourcePort: "43210",
	}

	scanner, err := NewScanner(opts)
	require.NoError(t, err)
	require.NotNil(t, scanner.ListenHandler)
	assert.Equal(t, 43210, scanner.ListenHandler.Port)

	bpf := BuildBPFFilter()
	if bpf != "" {
		assert.Contains(t, bpf, "tcp")
	}
}

func TestNewScanner_WithInvalidSourcePort(t *testing.T) {
	opts := &Options{
		ScanType:   TypeConnect,
		SourcePort: "invalid-port",
	}

	scanner, err := NewScanner(opts)
	assert.Error(t, err)
	assert.Nil(t, scanner)
}

func TestNewScanner_WithInvalidSourcePort_ReleasesHandler(t *testing.T) {
	origHandlers := ListenHandlers
	defer func() {
		listenHandlersMu.Lock()
		ListenHandlers = origHandlers
		listenHandlersMu.Unlock()
	}()

	initialCount := len(ListenHandlers)
	opts := &Options{
		ScanType:   TypeConnect,
		SourcePort: "-1",
	}

	scanner, err := NewScanner(opts)
	assert.Error(t, err)
	assert.Nil(t, scanner)
	assert.Equal(t, initialCount, len(ListenHandlers), "handler should be released on error")
}

func TestUpdateBPFFilter_NilHandlers_NoError(t *testing.T) {
	origHandlers := handlers
	handlers = nil
	defer func() {
		handlers = origHandlers
	}()

	err := UpdateBPFFilter()
	assert.NoError(t, err)
}

func TestBuildBPFFilter(t *testing.T) {
	bpf := BuildBPFFilter()
	if bpf != "" {
		assert.Contains(t, bpf, "tcp")
		assert.Contains(t, bpf, "udp")
	}
}
