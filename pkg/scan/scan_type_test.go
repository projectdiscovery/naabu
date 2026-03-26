package scan

import (
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRouter satisfies routing.Router so we can make PkgRouter non-nil in tests.
type stubRouter struct{ routing.Router }

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

func TestAcquire_SynScan_NoFreeHandlers_ReturnsError(t *testing.T) {
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
	ListenHandlers = []*ListenHandler{{Busy: true, Phase: &Phase{}}}

	_, err := Acquire(&Options{ScanType: TypeSyn})
	assert.Error(t, err, "should fail when all handlers are busy for syn scan")
}

func TestAcquire_SynScan_FreeHandler_Succeeds(t *testing.T) {
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
	freeHandler := &ListenHandler{Busy: false}
	ListenHandlers = []*ListenHandler{freeHandler}

	handler, err := Acquire(&Options{ScanType: TypeSyn})
	require.NoError(t, err)
	assert.Same(t, freeHandler, handler, "should return the free handler")
	assert.True(t, handler.Busy)
}

func TestNewScanner_SetsConnectScanType(t *testing.T) {
	scanner, err := NewScanner(&Options{ScanType: TypeConnect})
	require.NoError(t, err)
	assert.Equal(t, TypeConnect, scanner.ScanType)
}

func TestNewScanner_FallbackFromSynToConnect(t *testing.T) {
	origRouter := PkgRouter
	origPriv := privileges.IsPrivileged
	origHandlers := ListenHandlers
	defer func() {
		PkgRouter = origRouter
		privileges.IsPrivileged = origPriv
		ListenHandlers = origHandlers
	}()

	// Set up: router exists, privileged, but all handlers busy → Acquire fails for SYN
	PkgRouter = &stubRouter{}
	privileges.IsPrivileged = true
	ListenHandlers = []*ListenHandler{{Busy: true, Phase: &Phase{}}}

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
	assert.Nil(t, h.Phase)
}

func TestTypeConstants(t *testing.T) {
	assert.Equal(t, "s", TypeSyn)
	assert.Equal(t, "c", TypeConnect)
}
