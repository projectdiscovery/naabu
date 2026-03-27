package runner

import (
	"container/heap"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/prediction"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

// runPredictiveScan replaces the Blackrock scan loop with a priority-queue
// based scan. Ports are dequeued in priority order (most-likely-open first).
// When a port is found open, the OnReceive callback boosts correlated
// ports in the queue so they're scanned sooner. The user's port list is
// never modified, only the scan order changes.
//
// For SYN scans, a fast raw-socket sender bypasses gopacket serialization
// and the single-writer channel, sending packets directly via WriteTo.
func (r *Runner) runPredictiveScan(ctx context.Context, targets []*net.IPNet, targetsWithPort []string, shouldUseRawPackets bool) {
	model := prediction.DefaultModel()

	var targetsCount uint64
	for _, t := range targets {
		targetsCount += mapcidr.AddressCountIpnet(t)
	}

	srcPorts, totalCorrelations := model.Stats()
	gologger.Info().Msgf("Smart scan: model loaded (%d source ports, %d correlations)", srcPorts, totalCorrelations)

	// Fast SYN sender: bypasses gopacket + channel + single writer.
	// Falls back to standard path for Ethernet framing or IPv6.
	var sender *SYNSender
	if shouldUseRawPackets {
		var err error
		sender, err = newSYNSender(r.scanner.ListenHandler)
		if err != nil {
			gologger.Debug().Msgf("Fast sender unavailable (%s), using standard path\n", err)
		} else {
			gologger.Info().Msgf("Smart scan: fast SYN sender active (direct raw socket, zero-copy template)")
		}
	}

	// Atomic pointer so the OnReceive callback (fired from
	// TCPResultWorker goroutine) can safely read the current queue
	// while the main goroutine replaces it between retries.
	var queuePtr atomic.Pointer[portQueue]

	origOnReceive := r.scanner.OnReceive
	wrappedOnReceive := func(hr *result.HostResult) {
		if q := queuePtr.Load(); q != nil {
			for _, p := range hr.Ports {
				q.boostCorrelated(p.Port, model)
			}
		}
		if origOnReceive != nil {
			origOnReceive(hr)
		}
	}

	// OnReceive is read by TCPResultWorker. Phase.Set(scan.Scan) has
	// already been called by the caller, but no probes have been sent
	// yet so TcpChan is drained, the write here is ordered before any
	// SYN-ACK processing.
	r.scanner.OnReceive = wrappedOnReceive
	defer func() {
		r.scanner.OnReceive = origOnReceive
	}()

	// Pre-compute the target index so per-packet IP generation uses
	// uint32 arithmetic instead of big.Int.
	tgtIdx := buildTargetIndex(targets)

	// Monotonic seed for Blackrock: ensures each port gets a unique
	// IP permutation even when ports are dequeued in rapid succession.
	var brSeed int64

	timeout := r.options.GetTimeout()

	for retry := 0; retry < r.options.Retries; retry++ {
		knownOpen := r.collectOpenPorts()
		pq := newPortQueue(r.scanner.Ports, model, knownOpen)
		queuePtr.Store(pq)

		if retry == 0 {
			gologger.Info().Msgf("Smart scan: scanning %d ports across %d hosts (priority queue)", pq.len(), targetsCount)
		} else {
			gologger.Info().Msgf("Smart scan: retry %d/%d (%d ports remaining, %d already open)",
				retry, r.options.Retries-1, pq.len(), len(knownOpen))
		}

		for {
			p, ok := pq.pop()
			if !ok {
				break
			}
			brSeed++
			r.scanSinglePortOnTargets(ctx, targets, tgtIdx, p, targetsCount, shouldUseRawPackets, sender, brSeed)
			if sender != nil {
				sender.flush()
			}
		}

		if !shouldUseRawPackets {
			r.wgscan.Wait()
		}

		// Wait for in-flight SYN responses before the next retry
		// so the retry can skip IPs that responded.
		if shouldUseRawPackets && retry < r.options.Retries-1 {
			time.Sleep(timeout)
		}
	}

	// Detach the queue so late-arriving SYN-ACKs don't try to boost a
	// stale queue after we return.
	queuePtr.Store(nil)

	// Let last in-flight SYN packets get responses.
	if shouldUseRawPackets {
		time.Sleep(timeout)
	}

	r.scanTargetsWithPort(ctx, targetsWithPort, shouldUseRawPackets)
}

// scanSinglePortOnTargets scans one port across all target IPs.
//
// When sender is non-nil (fast SYN path), the entire hot loop avoids
// big.Int, gopacket, channels, and most string allocations:
//
//	IP generation:  uint32 add + shift        (~10ns)
//	IP formatting:  manual decimal formatter   (~25ns)
//	Packet build:   template patch + checksum  (~15ns)
//	Send:           direct WriteTo syscall     (~2µs)
//	                                    total  ~2.1µs/pkt -> ~475K pps
//
// The rate limiter is the only intentional throttle.
func (r *Runner) scanSinglePortOnTargets(ctx context.Context, targets []*net.IPNet, tgtIdx *targetIndex, p *port.Port, targetsCount uint64, shouldUseRawPackets bool, sender *SYNSender, seed int64) {
	payload := r.options.ConnectPayload
	b := blackrock.New(int64(targetsCount), seed)
	useFastPath := sender != nil && p.Protocol == protocol.TCP

	for i := int64(0); i < int64(targetsCount); i++ {
		if i&0x3ff == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

		ipIndex := b.Shuffle(i)

		// fast IPv4 path: uint32 arithmetic, no big.Int
		if useFastPath {
			dstIP, ip, isV4 := tgtIdx.pickIPv4(ipIndex)
			if !isV4 {
				// IPv6: fall back to standard path for this target.
				ipStr := r.PickIP(targets, ipIndex)
				if ipStr == "" {
					continue
				}
				r.limiter.Take()
				r.scanner.EnqueueTCP(ipStr, scan.Syn, p)
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
				continue
			}

			if r.excludedIpsNP != nil && !r.excludedIpsNP.ValidateAddress(ip) {
				continue
			}
			if r.scanner.ScanResults.HasSkipped(ip) {
				continue
			}
			if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
				hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
				gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", ip, hosts)
				r.scanner.ScanResults.AddSkipped(ip)
				continue
			}
			if r.scanner.ScanResults.IPHasPort(ip, p) {
				continue
			}
			if !r.canIScanIfCDN(ip, p) {
				continue
			}

			r.limiter.Take()
			if err := sender.send(dstIP, uint16(p.Port)); err != nil {
				gologger.Debug().Msgf("fast send error %s:%d: %s\n", ip, p.Port, err)
			}
			if r.options.EnableProgressBar {
				r.stats.IncrementCounter("packets", 1)
			}
			continue
		}

		// standard path (CONNECT scan, UDP, no fast sender)
		ip := r.PickIP(targets, ipIndex)
		if ip == "" {
			continue
		}
		if r.excludedIpsNP != nil && !r.excludedIpsNP.ValidateAddress(ip) {
			continue
		}
		if r.scanner.ScanResults.HasSkipped(ip) {
			continue
		}
		if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
			hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
			gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", ip, hosts)
			r.scanner.ScanResults.AddSkipped(ip)
			continue
		}

		if shouldUseRawPackets {
			if r.scanner.ScanResults.IPHasPort(ip, p) {
				continue
			}
			if !r.canIScanIfCDN(ip, p) {
				continue
			}
			r.limiter.Take()
			switch p.Protocol {
			case protocol.TCP:
				r.scanner.EnqueueTCP(ip, scan.Syn, p)
			case protocol.UDP:
				r.scanner.EnqueueUDP(ip, p)
			}
		} else {
			if r.scanner.ScanResults.IPHasPort(ip, p) {
				continue
			}
			if !r.canIScanIfCDN(ip, p) {
				continue
			}
			r.wgscan.Add()
			go r.handleHostPort(ctx, ip, payload, p)
		}

		if r.options.EnableProgressBar {
			r.stats.IncrementCounter("packets", 1)
		}
	}
}

// scanTargetsWithPort handles explicit ip:port targets.
func (r *Runner) scanTargetsWithPort(ctx context.Context, targetsWithPort []string, shouldUseRawPackets bool) {
	payload := r.options.ConnectPayload
	for _, targetWithPort := range targetsWithPort {
		ip, p, err := net.SplitHostPort(targetWithPort)
		if err != nil {
			gologger.Debug().Msgf("Skipping %s: %v\n", targetWithPort, err)
			continue
		}
		pp, err := strconv.Atoi(p)
		if err != nil {
			gologger.Debug().Msgf("Skipping %s, could not cast port %s: %v\n", targetWithPort, p, err)
			continue
		}
		portMeta := port.Port{Port: pp, Protocol: protocol.TCP}
		if shouldUseRawPackets {
			r.RawSocketEnumeration(ctx, ip, &portMeta)
		} else {
			r.wgscan.Add()
			go r.handleHostPort(ctx, ip, payload, &portMeta)
		}
		if r.options.EnableProgressBar {
			r.stats.IncrementCounter("packets", 1)
		}
	}
	r.wgscan.Wait()
}

// collectOpenPorts returns the deduplicated set of open port numbers
// found across all hosts so far.
func (r *Runner) collectOpenPorts() []int {
	return r.scanner.ScanResults.GetOpenPortNumbers()
}

// portQueue: a thread-safe max-heap that maintains a port -> index map so
// correlated ports can be boosted in O(log n) via heap.Fix.

type pqItem struct {
	port     *port.Port
	priority float64
	heapIdx  int
}

type portQueue struct {
	mu    sync.Mutex
	items []*pqItem
	index map[int]int // port number -> position in heap
}

// heap.Interface, called only while mu is held by the public methods.
func (pq *portQueue) Len() int { return len(pq.items) }
func (pq *portQueue) Less(i, j int) bool {
	if pq.items[i].priority != pq.items[j].priority {
		return pq.items[i].priority > pq.items[j].priority
	}
	return pq.items[i].port.Port < pq.items[j].port.Port
}
func (pq *portQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
	pq.items[i].heapIdx = i
	pq.items[j].heapIdx = j
	pq.index[pq.items[i].port.Port] = i
	pq.index[pq.items[j].port.Port] = j
}
func (pq *portQueue) Push(x interface{}) {
	item := x.(*pqItem)
	item.heapIdx = len(pq.items)
	pq.index[item.port.Port] = item.heapIdx
	pq.items = append(pq.items, item)
}
func (pq *portQueue) Pop() interface{} {
	old := pq.items
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.heapIdx = -1
	pq.items = old[:n-1]
	delete(pq.index, item.port.Port)
	return item
}

func newPortQueue(ports []*port.Port, model *prediction.Model, knownOpen []int) *portQueue {
	rank := buildPopularityRank()

	pq := &portQueue{
		items: make([]*pqItem, 0, len(ports)),
		index: make(map[int]int, len(ports)),
	}

	for _, p := range ports {
		r, ok := rank[p.Port]
		if !ok {
			r = 100000 + p.Port
		}
		pri := 1.0 / float64(r) // rank 1 -> 1.0, rank 100 -> 0.01

		// Boost from correlations with already-known open ports
		for _, open := range knownOpen {
			if corr := model.GetCorrelations(open); corr != nil {
				if prob, ok := corr[p.Port]; ok && prob > pri {
					pri = prob
				}
			}
		}

		heap.Push(pq, &pqItem{port: p, priority: pri})
	}

	return pq
}

func (pq *portQueue) pop() (*port.Port, bool) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	if len(pq.items) == 0 {
		return nil, false
	}
	item := heap.Pop(pq).(*pqItem)
	return item.port, true
}

// boostCorrelated is called from OnReceive when a port is found open.
// It increases the priority of every port correlated with the newly
// discovered open port, causing the heap to surface them sooner.
func (pq *portQueue) boostCorrelated(openPort int, model *prediction.Model) {
	corr := model.GetCorrelations(openPort)
	if len(corr) == 0 {
		return
	}

	pq.mu.Lock()
	defer pq.mu.Unlock()

	for targetPort, prob := range corr {
		idx, ok := pq.index[targetPort]
		if !ok {
			continue // already scanned / not in user's list
		}
		if prob > pq.items[idx].priority {
			pq.items[idx].priority = prob
			heap.Fix(pq, idx)
		}
	}
}

func (pq *portQueue) len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.items)
}

func buildPopularityRank() map[int]int {
	rank := make(map[int]int, 1200)
	idx := 1
	for _, segment := range strings.Split(NmapTop1000, ",") {
		segment = strings.TrimSpace(segment)
		if strings.Contains(segment, "-") {
			parts := strings.Split(segment, "-")
			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil {
				continue
			}
			for p := start; p <= end; p++ {
				rank[p] = idx
				idx++
			}
		} else {
			p, err := strconv.Atoi(segment)
			if err != nil {
				continue
			}
			rank[p] = idx
			idx++
		}
	}
	return rank
}
