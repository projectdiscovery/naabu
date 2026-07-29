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
// so every index is visited by exactly one worker. fn returning false stops the
// walk early (used for context cancellation).
func forEachWorkerIndex(worker, workers int, rng int64, fn func(int64) bool) {
	if workers < 1 {
		workers = 1
	}
	for index := int64(worker); index < rng; index += int64(workers) {
		if !fn(index) {
			return
		}
	}
}

// buildTxSenders creates the fan-out senders for the multi-core transmit path.
// The first slot reuses the already-created base sender; additional workers own
// independent raw sockets and batch buffers so both userspace batching and the
// kernel transmit path can run concurrently. Sockets are opened once and reused
// across retries (closeTxSenders frees the extra ones), avoiding a fresh
// open/close of every worker socket on each retry pass.
func (r *Runner) buildTxSenders(base *SYNSender, rng int64) []*SYNSender {
	n := effectiveTxWorkers(r.options.TxWorkers, r.options.Rate, rng, base != nil && base.batch != nil)
	senders := make([]*SYNSender, 1, n)
	senders[0] = base
	for i := 1; i < n; i++ {
		s, err := newWorkerSYNSender(r.scanner.ListenHandler)
		if err != nil {
			gologger.Debug().Msgf("tx worker %d sender unavailable (%s), reducing fan-out to %d\n", i, err, i)
			break
		}
		senders = append(senders, s)
	}
	return senders
}

// closeTxSenders releases the extra worker sockets built by buildTxSenders. The
// base sender (index 0) wraps the shared listen handler and is closed elsewhere.
func closeTxSenders(senders []*SYNSender) {
	for i := 1; i < len(senders); i++ {
		senders[i].close()
	}
}

// runFastTx fans the fast SYN send loop across the pre-built senders, each with
// its own raw sender, batch buffer and rate pacer, to overcome the single-core
// transmit ceiling. The global rate is split evenly across workers. Senders are
// owned by the caller and reused across retries, so this does not close them.
//
// Note: per-index resume bookkeeping is intentionally skipped on this path - it
// is inherently serial and meaningless once sends are fanned out; resume falls
// back to the standard single-worker loop.
// tierPortIdx maps a within-tier port position to an index into scanner.Ports;
// indexBase offsets this tier's local indices into the global index space so
// shard slicing stays disjoint across tiers. See porttiers.go.
func (r *Runner) runFastTx(ctx context.Context, b *blackrock.BlackRock, rng, indexBase int64, tierPortIdx []int,
	targets []*net.IPNet, tgtIdx *targetIndex, senders []*SYNSender, payload string, raw bool) {

	n := len(senders)
	if n == 0 {
		return
	}

	var wg sync.WaitGroup
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func(worker int, sender *SYNSender) {
			defer wg.Done()
			pace := newPacer(rateForWorker(r.options.Rate, n, worker))
			forEachWorkerIndex(worker, n, rng, func(index int64) bool {
				select {
				case <-ctx.Done():
					return false
				default:
				}
				r.fastScanIndex(ctx, b, index, indexBase, tierPortIdx, targets, tgtIdx, sender, pace, payload, raw)
				return true
			})
			if err := sender.flush(); err != nil {
				if isCongestion(err) {
					pace.onCongestion()
				}
				gologger.Debug().Msgf("tx worker %d final flush failed: %s\n", worker, err)
			}
		}(w, senders[w])
	}
	wg.Wait()

	// Drain any fallback (IPv6/connect) probes handed off to handleHostPort.
	r.wgscan.Wait()
}

// rateForWorker splits the configured global rate without dropping the
// remainder, while keeping the sum of all worker rates exactly equal to rate.
func rateForWorker(rate, workers, worker int) int {
	if rate <= 0 {
		return rate
	}
	base := rate / workers
	if worker < rate%workers {
		base++
	}
	return base
}

// effectiveTxWorkers avoids opening sockets and scheduling goroutines that
// cannot do useful work. On Linux, one sender can batch synBatchSize probes
// into a single sendmmsg call, so fan-out below that boundary only adds partial
// flushes. Non-batched platforms are capped by probe count instead.
func effectiveTxWorkers(requested, rate int, rng int64, batched bool) int {
	if requested < 1 {
		requested = 1
	}
	if rate > 0 && requested > rate {
		requested = rate
	}
	usefulWork := rng
	if batched && rng > 0 {
		usefulWork = (rng + synBatchSize - 1) / synBatchSize
	}
	if usefulWork > 0 && int64(requested) > usefulWork {
		requested = int(usefulWork)
	}
	return requested
}

// fastScanIndex processes a single Blackrock index on the fast SYN path. It is
// safe for concurrent use: the result store is mutex-protected, Blackrock.Shuffle
// is pure, and each caller supplies its own sender and pacer.
func (r *Runner) fastScanIndex(ctx context.Context, b *blackrock.BlackRock, index, indexBase int64, tierPortIdx []int,
	targets []*net.IPNet, tgtIdx *targetIndex, sender *SYNSender, pace *pacer, payload string, raw bool) {

	// Distributed sharding: only handle this node's slice. Shard membership is
	// decided on the global index so slices stay disjoint across tiers.
	if !r.options.inShard(indexBase + index) {
		return
	}

	tierPortsCount := int64(len(tierPortIdx))
	if tierPortsCount == 0 {
		return
	}
	xxx := b.Shuffle(index)
	ipIndex := xxx / tierPortsCount
	portIndex := tierPortIdx[int(xxx%tierPortsCount)]

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
