package runner

import (
	"context"
	"net"
	"sync"

	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

// forEachWorkerIndex walks the strided slice of [0,rng) owned by a given worker.
// Workers 0..workers-1 partition the index space by residue (index % workers),
// so every index is visited by exactly one worker.
func forEachWorkerIndex(worker, workers int, rng int64, fn func(int64)) {
	if workers < 1 {
		workers = 1
	}
	for index := int64(worker); index < rng; index += int64(workers) {
		fn(index)
	}
}

// runFastTx fans the fast SYN send loop across r.options.TxWorkers goroutines,
// each with its own raw sender, batch buffer and rate pacer, to overcome the
// single-core transmit ceiling. The global rate is split evenly across workers.
//
// Note: per-index resume bookkeeping is intentionally skipped on this path - it
// is inherently serial and meaningless once sends are fanned out; resume falls
// back to the standard single-worker loop.
func (r *Runner) runFastTx(ctx context.Context, b *blackrock.BlackRock, rng int64, portsCount uint64,
	targets []*net.IPNet, tgtIdx *targetIndex, base *SYNSender, payload string, raw bool) {

	n := r.options.TxWorkers
	if n < 1 {
		n = 1
	}

	// One sender per worker; the first reuses the already-created base sender.
	// Additional senders share the same raw fd but keep independent batch
	// buffers, so userspace batching does not contend.
	senders := make([]*SYNSender, 1, n)
	senders[0] = base
	for i := 1; i < n; i++ {
		s, err := newSYNSender(r.scanner.ListenHandler)
		if err != nil {
			gologger.Debug().Msgf("tx worker %d sender unavailable (%s), reducing fan-out to %d\n", i, err, i)
			break
		}
		senders = append(senders, s)
	}
	n = len(senders)

	perWorkerRate := r.options.Rate
	if perWorkerRate > 0 {
		perWorkerRate /= n
		if perWorkerRate < 1 {
			perWorkerRate = 1
		}
	}

	var wg sync.WaitGroup
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func(worker int, sender *SYNSender) {
			defer wg.Done()
			pace := newPacer(perWorkerRate)
			forEachWorkerIndex(worker, n, rng, func(index int64) {
				r.fastScanIndex(ctx, b, index, portsCount, targets, tgtIdx, sender, pace, payload, raw)
			})
			_ = sender.flush()
		}(w, senders[w])
	}
	wg.Wait()

	// Drain any fallback (IPv6/connect) probes handed off to handleHostPort.
	r.wgscan.Wait()
}

// fastScanIndex processes a single Blackrock index on the fast SYN path. It is
// safe for concurrent use: the result store is mutex-protected, Blackrock.Shuffle
// is pure, and each caller supplies its own sender and pacer.
func (r *Runner) fastScanIndex(ctx context.Context, b *blackrock.BlackRock, index int64, portsCount uint64,
	targets []*net.IPNet, tgtIdx *targetIndex, sender *SYNSender, pace *pacer, payload string, raw bool) {

	// Distributed sharding: only handle this node's slice.
	if !r.options.inShard(index) {
		return
	}

	xxx := b.Shuffle(index)
	ipIndex := xxx / int64(portsCount)
	portIndex := int(xxx % int64(portsCount))

	var (
		dstIP4 [4]byte
		isV4   bool
		ip     string
		srcSum uint32
	)
	if sender != nil {
		dstIP4, ip, srcSum, isV4 = tgtIdx.pickIPv4(ipIndex)
	}
	if ip == "" {
		ip = r.PickIP(targets, ipIndex)
	}

	if r.excludedIpsNP != nil && !r.excludedIpsNP.ValidateAddress(ip) {
		return
	}

	port := r.PickPort(portIndex)

	if r.scanner.ScanResults.HasSkipped(ip) {
		return
	}
	if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
		hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
		gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", ip, hosts)
		r.scanner.ScanResults.AddSkipped(ip)
		return
	}

	if raw {
		if sender != nil && isV4 && port.Protocol == protocol.TCP {
			if r.scanner.ScanResults.IPHasPort(ip, port) {
				return
			}
			if !r.canIScanIfCDN(ip, port) {
				return
			}
			pace.wait()
			if err := sender.send(dstIP4, srcSum, uint16(port.Port)); err != nil {
				if isCongestion(err) {
					pace.onCongestion()
				}
				gologger.Debug().Msgf("fast send error %s:%d: %s\n", ip, port.Port, err)
			}
		} else {
			r.RawSocketEnumeration(ctx, ip, port)
		}
	} else {
		r.wgscan.Add()
		go r.handleHostPort(ctx, ip, payload, port)
	}

	if r.options.EnableProgressBar {
		r.stats.IncrementCounter("packets", 1)
	}
}
