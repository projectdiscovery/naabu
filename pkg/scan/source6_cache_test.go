package scan

import (
	"net"
	"sync"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"github.com/stretchr/testify/require"
)

// countingRouter records how many times Route is called and returns a fixed
// source IP, so we can assert the destination cache collapses per-packet lookups.
type countingRouter struct {
	routing.Router
	mu    sync.Mutex
	calls int
	src   net.IP
}

func (c *countingRouter) Route(dst net.IP) (*net.Interface, net.IP, net.IP, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return nil, nil, c.src, nil
}

func resetSrc6Cache() {
	src6CacheMu.Lock()
	src6Cache = map[[16]byte]net.IP{}
	src6CacheMu.Unlock()
}

func TestSourceIP6ForCachesPerDestination(t *testing.T) {
	orig := PkgRouter
	t.Cleanup(func() { PkgRouter = orig; resetSrc6Cache() })
	resetSrc6Cache()

	want := net.ParseIP("2001:db8::1")
	cr := &countingRouter{src: want}
	PkgRouter = cr

	dst := net.ParseIP("2001:db8::10")
	for i := 0; i < 50; i++ {
		got := sourceIP6For(dst)
		require.True(t, want.Equal(got), "iter %d: got %v want %v", i, got, want)
	}
	require.Equal(t, 1, cr.calls, "same destination should be looked up once")

	// A different destination is a separate cache entry.
	_ = sourceIP6For(net.ParseIP("2001:db8::11"))
	require.Equal(t, 2, cr.calls)
}

func TestSourceIP6ForNilRouter(t *testing.T) {
	orig := PkgRouter
	t.Cleanup(func() { PkgRouter = orig; resetSrc6Cache() })
	resetSrc6Cache()

	PkgRouter = nil
	require.Nil(t, sourceIP6For(net.ParseIP("2001:db8::1")))
}

func TestSourceIP6ForRouteFailureNotCached(t *testing.T) {
	orig := PkgRouter
	t.Cleanup(func() { PkgRouter = orig; resetSrc6Cache() })
	resetSrc6Cache()

	// nil source from the router must not be cached, so a later success works.
	failing := &countingRouter{src: nil}
	PkgRouter = failing
	require.Nil(t, sourceIP6For(net.ParseIP("2001:db8::1")))
	require.Nil(t, sourceIP6For(net.ParseIP("2001:db8::1")))
	require.Equal(t, 2, failing.calls, "failed lookups must not be cached")
}
