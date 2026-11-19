package runner

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/mapcidr"
	"github.com/stretchr/testify/require"
)

type logCapture struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (c *logCapture) Write(data []byte, _ levels.Level) {
	c.mu.Lock()
	c.b.Write(data)
	c.mu.Unlock()
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}

func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	logs := &logCapture{}
	gologger.DefaultLogger.SetWriter(logs)
	t.Cleanup(func() {
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
	})
	return logs
}

func TestWithMaxRuntime(t *testing.T) {
	r := &Runner{options: &Options{}}
	ctx, stop := r.withMaxRuntime(context.Background())
	stop()
	require.NoError(t, ctx.Err(), "no limit must leave the context alone")

	r.options.MaxRuntime = 20 * time.Millisecond
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	ctx, stop = r.withMaxRuntime(parent)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("scan context must expire after max runtime")
	}
	require.ErrorIs(t, context.Cause(ctx), errMaxRuntime)
	require.NoError(t, parent.Err(), "receivers and -sV keep the parent context")
	stop()
	// The partial-results warning is posted asynchronously. Let it land before
	// a later test installs its own log capture.
	time.Sleep(50 * time.Millisecond)
}

// A finished scan still warms up for longer than the budget. That wait is result
// collection, so it must not be reported as a partial scan.
func TestMaxRuntimeWarmupDoesNotWarn(t *testing.T) {
	logs := captureLogs(t)
	r, err := NewRunner(&Options{
		Host:       []string{"127.0.0.1"},
		Ports:      "1",
		ScanType:   ConnectScan,
		Rate:       1000,
		Retries:    1,
		Timeout:    200 * time.Millisecond,
		MaxRuntime: 300 * time.Millisecond,
		WarmUpTime: 1,
	})
	require.NoError(t, err)
	defer r.Close() //nolint:errcheck

	start := time.Now()
	require.NoError(t, r.RunEnumeration(context.Background()))
	require.Greater(t, time.Since(start), 700*time.Millisecond, "warm-up still runs after the budget")
	require.NotContains(t, logs.String(), "Max runtime 300ms")
}

// Stream mode used to walk every port of the current target after the budget
// ran out. A long port list at a low rate must stop and say the results are partial.
func TestStreamMaxRuntimeStopsPortList(t *testing.T) {
	logs := captureLogs(t)
	r, err := NewRunner(&Options{
		Host:       []string{"127.0.0.1"},
		Ports:      "1-200",
		ScanType:   ConnectScan,
		Stream:     true,
		Rate:       2,
		Retries:    1,
		Timeout:    200 * time.Millisecond,
		MaxRuntime: 400 * time.Millisecond,
	})
	require.NoError(t, err)
	defer r.Close() //nolint:errcheck

	start := time.Now()
	require.NoError(t, r.RunEnumeration(context.Background()))
	require.Less(t, time.Since(start), 5*time.Second, "the port list must not be scanned after the budget")
	require.Contains(t, logs.String(), "Max runtime")
}

func TestEachCIDRAddressMatchesMapcidr(t *testing.T) {
	for _, cidr := range []string{"192.0.2.0/30", "192.0.2.5/32", "2001:db8::/126"} {
		var got []string
		stopped, err := eachCIDRAddress(context.Background(), cidr, func(ip string) bool {
			got = append(got, ip)
			return true
		})
		require.NoError(t, err)
		require.False(t, stopped)
		ch, err := mapcidr.IPAddressesAsStream(cidr)
		require.NoError(t, err)
		var want []string
		for ip := range ch {
			want = append(want, ip)
		}
		require.Equal(t, want, got, cidr)
	}
}

func TestEachCIDRAddressLeavesAWideRange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		n       int
		stopped bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		n := 0
		stopped, err := eachCIDRAddress(ctx, "fd00::/64", func(string) bool {
			n++
			if n == 3 {
				cancel()
			}
			return true
		})
		done <- result{n: n, stopped: stopped, err: err}
	}()
	select {
	case got := <-done:
		require.NoError(t, got.err)
		require.True(t, got.stopped)
		require.Equal(t, 3, got.n)
	case <-time.After(2 * time.Second):
		t.Fatal("address walk must stop when the context is cancelled")
	}
}
