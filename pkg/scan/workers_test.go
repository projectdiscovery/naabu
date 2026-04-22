package scan

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := NewScanner(&Options{})
	require.NoError(t, err)
	require.NotNil(t, s)
	require.NotNil(t, s.ListenHandler)
	s.ListenHandler.TcpChan = make(chan *PkgResult, chanSize)
	s.ListenHandler.UdpChan = make(chan *PkgResult, chanSize)
	s.ListenHandler.HostDiscoveryChan = make(chan *PkgResult, chanSize)
	return s
}

func newManualScanner(t *testing.T, handler *ListenHandler) *Scanner {
	t.Helper()
	iprang, err := ipranger.New()
	require.NoError(t, err)
	return &Scanner{
		ListenHandler:        handler,
		ScanResults:          result.NewResult(),
		HostDiscoveryResults: result.NewResult(),
		IPRanger:             iprang,
	}
}

func TestStartWorkersAndClose(t *testing.T) {
	s := newTestScanner(t)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	cancel()
	err := s.Close()
	assert.NoError(t, err)
	assert.Nil(t, s.ListenHandler)
}

func TestCloseWithoutStartWorkers(t *testing.T) {
	s := newTestScanner(t)

	err := s.Close()
	assert.NoError(t, err)
	assert.Nil(t, s.ListenHandler)
}

func TestCloseWaitsForWorkers(t *testing.T) {
	s := newTestScanner(t)
	s.ListenHandler.Phase = &Phase{}
	s.ListenHandler.Phase.Set(Scan)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	s.ListenHandler.TcpChan <- &PkgResult{ipv4: "1.2.3.4", port: &port.Port{Port: 80, Protocol: protocol.TCP}}

	time.Sleep(50 * time.Millisecond)

	cancel()

	done := make(chan struct{})
	go func() {
		_ = s.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return in time — workers may be stuck")
	}
}

func TestSequentialScannerReuse(t *testing.T) {
	handler := &ListenHandler{
		Phase:              &Phase{},
		TcpChan:            make(chan *PkgResult, chanSize),
		UdpChan:            make(chan *PkgResult, chanSize),
		HostDiscoveryChan:  make(chan *PkgResult, chanSize),
	}

	for i := 0; i < 5; i++ {
		handler.Busy = true
		handler.Phase = &Phase{}
		handler.Phase.Set(Scan)

		s := newManualScanner(t, handler)

		ctx, cancel := context.WithCancel(context.Background())
		s.StartWorkers(ctx)

		cancel()

		s.workersWg.Wait()
		handler.Busy = false
	}
}

func TestWorkersExitBeforeHandlerRelease(t *testing.T) {
	handler := &ListenHandler{
		Phase:              &Phase{},
		TcpChan:            make(chan *PkgResult, chanSize),
		UdpChan:            make(chan *PkgResult, chanSize),
		HostDiscoveryChan:  make(chan *PkgResult, chanSize),
	}

	var workerExitedFirst atomic.Bool

	s := newManualScanner(t, handler)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	cancel()

	go func() {
		s.workersWg.Wait()
		workerExitedFirst.Store(true)
	}()

	time.Sleep(200 * time.Millisecond)

	assert.True(t, workerExitedFirst.Load(), "workers should exit after context cancel before handler is reused")
}

func TestNoResponseLostBetweenSequentialScanners(t *testing.T) {
	s1 := newTestScanner(t)
	handler := s1.ListenHandler

	handler.Phase.Set(Scan)

	ctx1, cancel1 := context.WithCancel(context.Background())
	s1.StartWorkers(ctx1)
	cancel1()
	s1.workersWg.Wait()
	handler.Phase.Set(Done)

	handler.Phase = &Phase{}
	handler.Phase.Set(Scan)

	s2 := newTestScanner(t)
	s2.ListenHandler = handler

	err := s2.IPRanger.Add("192.168.1.1")
	require.NoError(t, err)

	ctx2, cancel2 := context.WithCancel(context.Background())
	s2.StartWorkers(ctx2)

	handler.TcpChan <- &PkgResult{
		ipv4: "192.168.1.1",
		port: &port.Port{Port: 80, Protocol: protocol.TCP},
	}

	time.Sleep(100 * time.Millisecond)

	assert.True(t, s2.ScanResults.IPHasPort("192.168.1.1", &port.Port{Port: 80, Protocol: protocol.TCP}),
		"Scanner 2 should have received the response sent during its scan phase")

	cancel2()
	s2.workersWg.Wait()
}

func TestConcurrentCloseAndCreate(t *testing.T) {
	handler := &ListenHandler{
		Phase:              &Phase{},
		TcpChan:            make(chan *PkgResult, chanSize),
		UdpChan:            make(chan *PkgResult, chanSize),
		HostDiscoveryChan:  make(chan *PkgResult, chanSize),
	}

	const iterations = 20
	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		handler.Busy = true
		handler.Phase = &Phase{}
		handler.Phase.Set(Scan)

		s := newManualScanner(t, handler)

		ctx, cancel := context.WithCancel(context.Background())
		s.StartWorkers(ctx)

		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * time.Millisecond)
			handler.TcpChan <- &PkgResult{
				ipv4: "10.0.0.1",
				port: &port.Port{Port: 80, Protocol: protocol.TCP},
			}
		}()

		time.Sleep(10 * time.Millisecond)
		cancel()
		s.workersWg.Wait()
		handler.Busy = false
	}

	wg.Wait()
	// drain any leftover items from the channel
	for len(handler.TcpChan) > 0 {
		<-handler.TcpChan
	}
}

func TestTCPResultWorkerAddsToScanResults(t *testing.T) {
	s := newTestScanner(t)
	s.ListenHandler.Phase.Set(Scan)

	err := s.IPRanger.Add("10.0.0.1")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	s.ListenHandler.TcpChan <- &PkgResult{
		ipv4: "10.0.0.1",
		port: &port.Port{Port: 443, Protocol: protocol.TCP},
	}

	time.Sleep(100 * time.Millisecond)

	assert.True(t, s.ScanResults.IPHasPort("10.0.0.1", &port.Port{Port: 443, Protocol: protocol.TCP}))

	cancel()
	err = s.Close()
	assert.NoError(t, err)
}

func TestTCPResultWorkerDropsOutOfRangeIP(t *testing.T) {
	s := newTestScanner(t)
	s.ListenHandler.Phase.Set(Scan)

	err := s.IPRanger.Add("10.0.0.1")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	s.ListenHandler.TcpChan <- &PkgResult{
		ipv4: "10.0.0.99",
		port: &port.Port{Port: 80, Protocol: protocol.TCP},
	}

	time.Sleep(100 * time.Millisecond)

	assert.False(t, s.ScanResults.IPHasPort("10.0.0.99", &port.Port{Port: 80, Protocol: protocol.TCP}))

	cancel()
	err = s.Close()
	assert.NoError(t, err)
}

func TestICMPResultWorkerAddsDuringHostDiscovery(t *testing.T) {
	s := newTestScanner(t)
	s.ListenHandler.Phase.Set(HostDiscovery)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	s.ListenHandler.HostDiscoveryChan <- &PkgResult{ipv4: "10.0.0.5"}

	time.Sleep(100 * time.Millisecond)

	assert.True(t, s.HostDiscoveryResults.HasIP("10.0.0.5"))

	cancel()
	err := s.Close()
	assert.NoError(t, err)
}

func TestTCPResultWorkerIgnoresDuringDonePhase(t *testing.T) {
	s := newTestScanner(t)
	s.ListenHandler.Phase.Set(Done)

	err := s.IPRanger.Add("10.0.0.1")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	s.ListenHandler.TcpChan <- &PkgResult{
		ipv4: "10.0.0.1",
		port: &port.Port{Port: 80, Protocol: protocol.TCP},
	}

	time.Sleep(100 * time.Millisecond)

	assert.False(t, s.ScanResults.IPHasPort("10.0.0.1", &port.Port{Port: 80, Protocol: protocol.TCP}))

	cancel()
	err = s.Close()
	assert.NoError(t, err)
}

func TestOnReceiveCalledDuringScan(t *testing.T) {
	s := newTestScanner(t)
	s.ListenHandler.Phase.Set(Scan)

	err := s.IPRanger.Add("10.0.0.1")
	require.NoError(t, err)

	var called atomic.Bool
	s.OnReceive = func(hr *result.HostResult) {
		called.Store(true)
		assert.Equal(t, "10.0.0.1", hr.IP)
		assert.Equal(t, 1, len(hr.Ports))
		assert.Equal(t, 80, hr.Ports[0].Port)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.StartWorkers(ctx)

	s.ListenHandler.TcpChan <- &PkgResult{
		ipv4: "10.0.0.1",
		port: &port.Port{Port: 80, Protocol: protocol.TCP},
	}

	time.Sleep(100 * time.Millisecond)

	assert.True(t, called.Load(), "OnReceive should have been called")

	cancel()
	err = s.Close()
	assert.NoError(t, err)
}
