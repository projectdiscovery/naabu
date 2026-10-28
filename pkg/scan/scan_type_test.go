package scan

import (
	"errors"
	"sync"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRouter satisfies routing.Router so we can make PkgRouter non-nil in tests.
type stubRouter struct{ routing.Router }

// withStubbedRawInfra wires the on-demand handler seam so the SYN Acquire path
// can be exercised without opening real raw sockets or pcap handles. The build
// function returns a fresh handler each call (or an error to simulate failure).
func withStubbedRawInfra(t *testing.T, infraOK bool, build func() (*ListenHandler, error)) {
	t.Helper()
	origRouter := PkgRouter
	origPriv := privileges.IsPrivileged
	origBuild := buildHandlerFn
	origEnsure := ensureRawInfraFn
	origHandlers := ListenHandlers
	t.Cleanup(func() {
		PkgRouter = origRouter
		privileges.IsPrivileged = origPriv
		buildHandlerFn = origBuild
		ensureRawInfraFn = origEnsure
		ListenHandlers = origHandlers
	})
	PkgRouter = &stubRouter{}
	privileges.IsPrivileged = true
	ListenHandlers = nil
	ensureRawInfraFn = func() bool { return infraOK }
	buildHandlerFn = build
}

func TestAcquire_ConnectScan_AlwaysSucceeds(t *testing.T) {
	opts := &Options{ScanType: TypeConnect}
	handler, err := Acquire(opts)
	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.True(t, handler.Busy)
}

func TestAcquire_ReturnsSameHandler(t *testing.T) {
	opts := &Options{ScanType: TypeConnect}
	handler, err := Acquire(opts)
	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.True(t, handler.Busy, "returned handler should have Busy=true")
}

func TestAcquire_ConnectScan_HandlerHasPhase(t *testing.T) {
	opts := &Options{ScanType: TypeConnect}
	handler, err := Acquire(opts)
	require.NoError(t, err)
	assert.NotNil(t, handler.Phase)
}

func TestAcquire_NilRouter_SucceedsForAnyScanType(t *testing.T) {
	origRouter := PkgRouter
	PkgRouter = nil
	defer func() { PkgRouter = origRouter }()

	for _, scanType := range []string{TypeSyn, TypeConnect, ""} {
		handler, err := Acquire(&Options{ScanType: scanType})
		require.NoError(t, err, "scanType=%q should succeed with nil router", scanType)
		assert.NotNil(t, handler)
		assert.True(t, handler.Busy)
	}
}

func TestAcquire_SynScan_InfraFailure_ReturnsError(t *testing.T) {
	withStubbedRawInfra(t, false, func() (*ListenHandler, error) {
		return NewListenHandler(), nil
	})

	_, err := Acquire(&Options{ScanType: TypeSyn})
	assert.Error(t, err, "should fail when raw infrastructure cannot start")
}

func TestAcquire_SynScan_BuildFailure_ReturnsError(t *testing.T) {
	withStubbedRawInfra(t, true, func() (*ListenHandler, error) {
		return nil, errors.New("no privileges")
	})

	_, err := Acquire(&Options{ScanType: TypeSyn})
	assert.Error(t, err, "build error should propagate")
}

func TestAcquire_SynScan_BuildsAndRegisters(t *testing.T) {
	built := &ListenHandler{Phase: &Phase{}}
	withStubbedRawInfra(t, true, func() (*ListenHandler, error) { return built, nil })

	handler, err := Acquire(&Options{ScanType: TypeSyn})
	require.NoError(t, err)
	assert.Same(t, built, handler, "should return the freshly built handler")
	assert.True(t, handler.Busy)
	assert.Contains(t, ListenHandlers, built, "handler must be registered for the readers")
}

func TestAcquireSynScanIsConcurrencySafe(t *testing.T) {
	withStubbedRawInfra(t, true, func() (*ListenHandler, error) {
		return &ListenHandler{Phase: &Phase{}}, nil
	})

	const n = 50
	var wg sync.WaitGroup
	got := make([]*ListenHandler, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if h, err := Acquire(&Options{ScanType: TypeSyn}); err == nil {
				got[i] = h
			}
		}(i)
	}
	wg.Wait()

	// Every concurrent Acquire gets its own distinct handler, and all are
	// registered exactly once (no lost updates to the shared slice).
	seen := map[*ListenHandler]bool{}
	for _, h := range got {
		require.NotNil(t, h)
		assert.Falsef(t, seen[h], "handler %p handed out more than once", h)
		seen[h] = true
	}
	listenHandlersMu.RLock()
	registered := len(ListenHandlers)
	listenHandlersMu.RUnlock()
	assert.Equal(t, n, registered, "all handlers should be registered")
}

func TestReleaseRemovesFromRegistry(t *testing.T) {
	origHandlers := ListenHandlers
	t.Cleanup(func() { ListenHandlers = origHandlers })

	// Distinct ports so testify's value-based Contains can tell them apart.
	h := &ListenHandler{Phase: &Phase{}, Busy: true, Port: 2}
	other := &ListenHandler{Phase: &Phase{}, Port: 1}
	ListenHandlers = []*ListenHandler{other, h}

	h.Release()

	assert.False(t, h.Busy)
	assert.NotContains(t, ListenHandlers, h, "released handler must be deregistered")
	assert.Contains(t, ListenHandlers, other, "other handlers must remain")
}

func TestNewScanner_SetsConnectScanType(t *testing.T) {
	scanner, err := NewScanner(&Options{ScanType: TypeConnect})
	require.NoError(t, err)
	assert.Equal(t, TypeConnect, scanner.ScanType)
}

func TestNewScanner_FallbackFromSynToConnect(t *testing.T) {
	// Privileged SYN scan whose handler build fails must fall back to connect.
	withStubbedRawInfra(t, true, func() (*ListenHandler, error) {
		return nil, errors.New("cannot open raw socket")
	})

	opts := &Options{ScanType: TypeSyn}
	scanner, err := NewScanner(opts)
	require.NoError(t, err)

	assert.Equal(t, TypeConnect, scanner.ScanType,
		"scanner should reflect connect scan after fallback from syn")
	assert.Equal(t, TypeConnect, opts.ScanType,
		"options should be mutated to connect after fallback")
	assert.NotNil(t, scanner.ListenHandler,
		"connect fallback should still provide a listen handler")
}

func TestNewScanner_SynWithNilRouter_KeepsSynType(t *testing.T) {
	origRouter := PkgRouter
	PkgRouter = nil
	defer func() { PkgRouter = origRouter }()

	// With nil router, Acquire succeeds immediately (treats as unprivileged)
	scanner, err := NewScanner(&Options{ScanType: TypeSyn})
	require.NoError(t, err)
	assert.Equal(t, TypeSyn, scanner.ScanType,
		"nil router causes Acquire to succeed without fallback, preserving syn type")
	assert.NotNil(t, scanner.ListenHandler)
}

func TestNewScanner_ConnectScanPreservesType(t *testing.T) {
	scanner, err := NewScanner(&Options{ScanType: TypeConnect})
	require.NoError(t, err)
	assert.Equal(t, TypeConnect, scanner.ScanType)
	assert.NotNil(t, scanner.ListenHandler)
}

func TestNewScanner_EmptyScanType_Succeeds(t *testing.T) {
	scanner, err := NewScanner(&Options{})
	require.NoError(t, err)
	assert.NotNil(t, scanner)
	assert.NotNil(t, scanner.ListenHandler)
}

func TestNewScanner_DefaultFields(t *testing.T) {
	opts := &Options{
		ScanType: TypeConnect,
		Retries:  3,
		Rate:     1000,
	}
	scanner, err := NewScanner(opts)
	require.NoError(t, err)
	assert.NotNil(t, scanner.ScanResults)
	assert.NotNil(t, scanner.HostDiscoveryResults)
	assert.NotNil(t, scanner.IPRanger)
}

func TestListenHandler_Release(t *testing.T) {
	h := NewListenHandler()
	h.Busy = true
	h.Release()
	assert.False(t, h.Busy)
	// Release keeps a valid idle Phase so the global pcap reader can safely
	// dereference it for stray packets while the handler sits in the pool.
	assert.NotNil(t, h.Phase)
	assert.True(t, h.Phase.Is(Init))
}

func TestTypeConstants(t *testing.T) {
	assert.Equal(t, "s", TypeSyn)
	assert.Equal(t, "c", TypeConnect)
}
