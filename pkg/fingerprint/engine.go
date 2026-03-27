package fingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"hash/fnv"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

// DialFunc abstracts TCP dialing to support proxies.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Engine orchestrates concurrent service fingerprinting using nmap service probes.
type Engine struct {
	db             *ProbeDB
	workers        int
	timeout        time.Duration
	connectTimeout time.Duration // separate, shorter timeout for TCP dial (default 3s)
	fastMode       bool
	dialer         DialFunc
	intensityMax   int
	matchCache     sync.Map // response hash → *matchCacheEntry (avoids re-matching identical banners)
}

// StreamResult is emitted by FingerprintStream for each identified service.
type StreamResult struct {
	IP      string
	Port    int
	Service *port.Service
}

type matchCacheEntry struct {
	result *MatchResult // nil = no match found
}

// New creates a fingerprint engine with parsed probes.
func New(db *ProbeDB, opts ...Option) *Engine {
	e := &Engine{
		db:             db,
		workers:        DefaultWorkers,
		timeout:        DefaultTimeout,
		connectTimeout: DefaultConnectTimeout,
		dialer:         defaultDialer,
		intensityMax:   7,
	}
	for _, o := range opts {
		o(e)
	}
	if e.connectTimeout > e.timeout {
		e.connectTimeout = e.timeout
	}
	return e
}

func defaultDialer(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Fingerprint runs probes against all targets and returns a map of "ip:port" -> Service.
func (e *Engine) Fingerprint(ctx context.Context, targets []Target) map[string]*port.Service {
	results := make(map[string]*port.Service)
	var mu sync.Mutex

	work := make(chan Target, len(targets))
	var wg sync.WaitGroup

	numWorkers := e.workers
	if numWorkers > len(targets) {
		numWorkers = len(targets)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				if ctx.Err() != nil {
					return
				}
				r := e.fingerprintOne(ctx, t)
				if r != nil {
					key := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
					mu.Lock()
					results[key] = r.ToService()
					mu.Unlock()
				}
			}
		}()
	}

	for _, t := range targets {
		work <- t
	}
	close(work)
	wg.Wait()

	return results
}

// FingerprintStream processes targets from a channel and emits results as
// they're identified. This enables pipeline fingerprinting: the caller can
// feed targets as ports are discovered during scanning, overlapping the scan
// and fingerprint phases to eliminate idle time between them.
func (e *Engine) FingerprintStream(ctx context.Context, targets <-chan Target) <-chan StreamResult {
	results := make(chan StreamResult, e.workers*2)

	var wg sync.WaitGroup
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				if ctx.Err() != nil {
					return
				}
				r := e.fingerprintOne(ctx, t)
				if r != nil {
					results <- StreamResult{
						IP:      t.IP,
						Port:    t.Port,
						Service: r.ToService(),
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// fingerprintOne runs probes against a single target in two phases:
//
// Phase 1 (parallel): NULL probe and all port-hinted probes run simultaneously.
// The NULL probe passively listens for banners while active probes (GetRequest,
// etc.) send data. First hard match wins and cancels the other probes. This
// eliminates the sequential bottleneck where HTTP targets wait 6s for NULL
// to timeout before GetRequest even starts.
//
// Phase 2 (sequential): remaining non-hinted probes run one at a time, sorted
// by rarity. Skipped entirely in fast mode.
func (e *Engine) fingerprintOne(ctx context.Context, t Target) *Result {
	if e.db == nil || len(e.db.Probes) == 0 {
		return nil
	}

	addr := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))

	isTLS := t.TLSDetected
	if !isTLS && !t.TLSChecked {
		isTLS = e.detectTLS(ctx, t)
	}

	hinted, fallback := e.classifyProbes(t.Port, isTLS)

	// Phase 1: run hinted probes in parallel
	type probeResult struct {
		hard *MatchResult
		soft *MatchResult
		tls  bool
	}

	var softResult *MatchResult
	var softTLS bool

	if len(hinted) > 0 {
		probeCtx, probeCancel := context.WithCancel(ctx)
		ch := make(chan probeResult, len(hinted))

		for _, sp := range hinted {
			sp := sp
			go func() {
				useTLS := isTLS
				if !useTLS && sp.SSLPorts != nil && sp.SSLPorts.Contains(t.Port) {
					useTLS = true
				}
				waitTimeout := sp.WaitDuration()
				if e.timeout > 0 && e.timeout < waitTimeout {
					waitTimeout = e.timeout
				}
				hard, soft := e.runProbe(probeCtx, sp, t, addr, useTLS, waitTimeout)
				ch <- probeResult{hard, soft, useTLS}
			}()
		}

		for i := 0; i < len(hinted); i++ {
			r := <-ch
			if r.hard != nil {
				probeCancel()
				return matchResultToResult(r.hard, r.tls, "")
			}
			if r.soft != nil && softResult == nil {
				softResult = r.soft
				softTLS = r.tls
			}
		}
		probeCancel()
	}

	// Phase 2: run fallback probes in small batches to overlap TCP setup.
	// Instead of connecting sequentially (each waiting for its own handshake),
	// batches of probes dial concurrently so only one RTT is paid per batch.
	const fallbackBatchSize = 4
	for i := 0; i < len(fallback); i += fallbackBatchSize {
		if ctx.Err() != nil {
			break
		}
		end := i + fallbackBatchSize
		if end > len(fallback) {
			end = len(fallback)
		}
		batch := fallback[i:end]

		if len(batch) == 1 {
			sp := batch[0]
			useTLS := isTLS
			if !useTLS && sp.SSLPorts != nil && sp.SSLPorts.Contains(t.Port) {
				useTLS = true
			}
			waitTimeout := sp.WaitDuration()
			if e.timeout > 0 && e.timeout < waitTimeout {
				waitTimeout = e.timeout
			}
			result, soft := e.runProbe(ctx, sp, t, addr, useTLS, waitTimeout)
			if result != nil {
				return matchResultToResult(result, useTLS, "")
			}
			if soft != nil && softResult == nil {
				softResult = soft
				softTLS = useTLS
			}
			continue
		}

		batchCtx, batchCancel := context.WithCancel(ctx)
		batchCh := make(chan probeResult, len(batch))
		for _, sp := range batch {
			sp := sp
			go func() {
				useTLS := isTLS
				if !useTLS && sp.SSLPorts != nil && sp.SSLPorts.Contains(t.Port) {
					useTLS = true
				}
				waitTimeout := sp.WaitDuration()
				if e.timeout > 0 && e.timeout < waitTimeout {
					waitTimeout = e.timeout
				}
				hard, soft := e.runProbe(batchCtx, sp, t, addr, useTLS, waitTimeout)
				batchCh <- probeResult{hard, soft, useTLS}
			}()
		}
		for j := 0; j < len(batch); j++ {
			r := <-batchCh
			if r.hard != nil {
				batchCancel()
				return matchResultToResult(r.hard, r.tls, "")
			}
			if r.soft != nil && softResult == nil {
				softResult = r.soft
				softTLS = r.tls
			}
		}
		batchCancel()
	}

	if softResult != nil {
		return matchResultToResult(softResult, softTLS, "")
	}

	return nil
}

// classifyProbes splits probes into hinted (run in parallel) and fallback
// (run sequentially) groups. Hinted probes are NULL + probes whose ports/sslports
// lists contain the target port.
func (e *Engine) classifyProbes(targetPort int, isTLS bool) (hinted, fallback []*ServiceProbe) {
	for _, sp := range e.db.Probes {
		if sp.Protocol != "TCP" {
			continue
		}
		if sp.Rarity > e.intensityMax {
			continue
		}

		isHinted := sp.Name == "NULL" ||
			(sp.Ports != nil && sp.Ports.Contains(targetPort)) ||
			(sp.SSLPorts != nil && sp.SSLPorts.Contains(targetPort))

		if isHinted {
			hinted = append(hinted, sp)
		} else if !e.fastMode {
			fallback = append(fallback, sp)
		}
	}

	sort.SliceStable(hinted, func(i, j int) bool {
		if hinted[i].Name == "NULL" {
			return true
		}
		if hinted[j].Name == "NULL" {
			return false
		}
		return hinted[i].Rarity < hinted[j].Rarity
	})

	sort.SliceStable(fallback, func(i, j int) bool {
		return fallback[i].Rarity < fallback[j].Rarity
	})

	return hinted, fallback
}

// runProbe sends a single probe and tries to match the response.
// Returns (hardMatch, softMatch). When the context is cancelled (e.g. another
// parallel probe found a match), the connection is closed immediately to
// unblock any in-progress reads.
func (e *Engine) runProbe(ctx context.Context, sp *ServiceProbe, t Target, addr string, useTLS bool, waitTimeout time.Duration) (*MatchResult, *MatchResult) {
	// Use a short connect timeout for the TCP dial, and a longer timeout for
	// the overall probe (TLS handshake + data exchange).
	dialCtx, dialCancel := context.WithTimeout(ctx, e.connectTimeout)
	conn, err := e.dialer(dialCtx, "tcp", addr)
	dialCancel()
	if err != nil {
		return nil, nil
	}

	probeCtx, probeCancel := context.WithTimeout(ctx, e.timeout)
	defer probeCancel()

	if useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         t.Host,
		})
		if err := tlsConn.HandshakeContext(probeCtx); err != nil {
			conn.Close()
			return nil, nil
		}
		conn = tlsConn
	}

	defer conn.Close()

	// Close the connection when context is cancelled so blocking reads
	// return immediately instead of waiting for their full timeout.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-probeCtx.Done():
			conn.Close()
		case <-done:
		}
	}()

	if len(sp.Data) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(e.timeout))
		if _, err := conn.Write(sp.Data); err != nil {
			return nil, nil
		}
	}

	allMatches := e.collectMatchSets(sp)

	readStart := time.Now()
	response, closedEarly := e.readResponseWithEarlyMatch(conn, waitTimeout, allMatches)

	if ctx.Err() != nil {
		return nil, nil
	}

	if len(response) == 0 {
		if closedEarly && sp.Name == "NULL" && sp.TCPWrappedMS > 0 {
			elapsed := time.Since(readStart)
			if elapsed < time.Duration(sp.TCPWrappedMS)*time.Millisecond {
				return &MatchResult{Service: "tcpwrapped"}, nil
			}
		}
		return nil, nil
	}

	return e.matchResponse(sp, allMatches, response)
}

// collectMatchSets gathers all match lists (probe + fallbacks) for early-match.
func (e *Engine) collectMatchSets(sp *ServiceProbe) [][]*Match {
	sets := [][]*Match{sp.Matches}
	if sp.Fallback != "" {
		for _, fbName := range strings.Split(sp.Fallback, ",") {
			fbName = strings.TrimSpace(fbName)
			if fbProbe := e.findProbe(fbName); fbProbe != nil {
				sets = append(sets, fbProbe.Matches)
			}
		}
	}
	return sets
}

// matchResponse tries all hard matches, then all soft matches including fallbacks.
func (e *Engine) matchResponse(sp *ServiceProbe, hardSets [][]*Match, response []byte) (*MatchResult, *MatchResult) {
	for _, matches := range hardSets {
		if result := e.tryMatches(matches, response); result != nil {
			return result, nil
		}
	}

	if soft := e.tryMatches(sp.SoftMatches, response); soft != nil {
		return nil, soft
	}
	if sp.Fallback != "" {
		for _, fbName := range strings.Split(sp.Fallback, ",") {
			fbName = strings.TrimSpace(fbName)
			if fbProbe := e.findProbe(fbName); fbProbe != nil {
				if soft := e.tryMatches(fbProbe.SoftMatches, response); soft != nil {
					return nil, soft
				}
			}
		}
	}

	return nil, nil
}

// readResponseWithEarlyMatch accumulates data from the connection, trying
// pattern matching after each chunk. If any hard match succeeds, it returns
// immediately without the follow-up read delay — banner services (SSH, FTP,
// SMTP) are identified in <10ms instead of waiting for more data.
func (e *Engine) readResponseWithEarlyMatch(conn net.Conn, waitTimeout time.Duration, matchSets [][]*Match) (response []byte, closedEarly bool) {
	deadline := time.Now().Add(waitTimeout)
	buf := make([]byte, 65535)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		_ = conn.SetReadDeadline(time.Now().Add(remaining))
		n, err := conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)

			for _, matches := range matchSets {
				if e.tryMatches(matches, response) != nil {
					return response, false
				}
			}

			if remaining > 200*time.Millisecond {
				_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n2, _ := conn.Read(buf)
				if n2 > 0 {
					response = append(response, buf[:n2]...)
				}
			}
			return response, false
		}

		if err != nil {
			if isConnectionClosed(err) {
				return nil, true
			}
			break
		}
	}

	return response, false
}

func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return !netErr.Timeout()
	}
	if os.IsTimeout(err) {
		return false
	}
	// EOF or connection reset = closed
	return true
}

// tryMatches runs response against a list of match directives.
// Three layers of optimization avoid running the regex engine unnecessarily:
//  1. Response cache: identical banners (by hash) return cached results instantly
//  2. Latin-1 conversion: done once and shared across all 3,997+ pattern checks
//  3. Literal prefix filter: patterns whose prefix doesn't appear in the response
//     are skipped without invoking the regex engine at all
func (e *Engine) tryMatches(matches []*Match, response []byte) *MatchResult {
	if len(matches) == 0 || len(response) == 0 {
		return nil
	}

	cacheKey := responseHash(matches, response)
	if cached, ok := e.matchCache.Load(cacheKey); ok {
		return cached.(*matchCacheEntry).result
	}

	latin1 := bytesToLatin1(response)
	var result *MatchResult

	for _, m := range matches {
		if !m.prefixMatches(latin1) {
			continue
		}
		match, err := m.Pattern.FindStringMatch(latin1)
		if err != nil || match == nil {
			continue
		}
		groups := match.Groups()
		strs := make([]string, len(groups))
		for i, g := range groups {
			strs[i] = g.String()
		}
		result = m.Apply(strs)
		break
	}

	e.matchCache.Store(cacheKey, &matchCacheEntry{result: result})
	return result
}

func responseHash(matches []*Match, response []byte) uint64 {
	h := fnv.New64a()
	var buf [8]byte
	for _, m := range matches {
		p := uintptr(unsafe.Pointer(m))
		buf[0] = byte(p)
		buf[1] = byte(p >> 8)
		buf[2] = byte(p >> 16)
		buf[3] = byte(p >> 24)
		buf[4] = byte(p >> 32)
		buf[5] = byte(p >> 40)
		buf[6] = byte(p >> 48)
		buf[7] = byte(p >> 56)
		_, _ = h.Write(buf[:])
	}
	_, _ = h.Write(response)
	return h.Sum64()
}

// detectTLS tries a TLS handshake on the target to determine if the port speaks TLS.
func (e *Engine) detectTLS(ctx context.Context, t Target) bool {
	if ctx.Err() != nil {
		return false
	}

	addr := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
	tlsTimeout := 2 * time.Second
	if e.timeout < tlsTimeout {
		tlsTimeout = e.timeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, tlsTimeout)
	defer cancel()

	conn, err := e.dialer(dialCtx, "tcp", addr)
	if err != nil {
		return false
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         t.Host,
	})

	_ = conn.SetDeadline(time.Now().Add(tlsTimeout))
	err = tlsConn.Handshake()
	conn.Close()

	return err == nil
}

// orderProbes selects and orders probes for a target port.
// Follows nmap's probe ordering:
//  1. NULL probe always first
//  2. Port-hinted probes (port in ports or sslports) sorted by rarity
//  3. Fallback probes (all others) sorted by rarity, only if not fast mode
func (e *Engine) orderProbes(targetPort int, isTLS bool) []*ServiceProbe {
	var hinted, fallback []*ServiceProbe

	for _, sp := range e.db.Probes {
		if sp.Protocol != "TCP" {
			continue
		}

		if sp.Rarity > e.intensityMax {
			continue
		}

		isHinted := false
		if sp.Ports != nil && sp.Ports.Contains(targetPort) {
			isHinted = true
		}
		if sp.SSLPorts != nil && sp.SSLPorts.Contains(targetPort) {
			isHinted = true
		}
		if sp.Name == "NULL" {
			isHinted = true
		}

		if isHinted {
			hinted = append(hinted, sp)
		} else if !e.fastMode {
			fallback = append(fallback, sp)
		}
	}

	sort.SliceStable(hinted, func(i, j int) bool {
		if hinted[i].Name == "NULL" {
			return true
		}
		if hinted[j].Name == "NULL" {
			return false
		}
		return hinted[i].Rarity < hinted[j].Rarity
	})

	sort.SliceStable(fallback, func(i, j int) bool {
		return fallback[i].Rarity < fallback[j].Rarity
	})

	return append(hinted, fallback...)
}

// FingerprintUDP runs UDP probes against targets.
func (e *Engine) FingerprintUDP(ctx context.Context, targets []Target) map[string]*port.Service {
	results := make(map[string]*port.Service)
	var mu sync.Mutex
	work := make(chan Target, len(targets))
	var wg sync.WaitGroup

	numWorkers := e.workers
	if numWorkers > len(targets) {
		numWorkers = len(targets)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				if ctx.Err() != nil {
					return
				}
				r := e.fingerprintUDPOne(ctx, t)
				if r != nil {
					key := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
					mu.Lock()
					results[key] = r.ToService()
					mu.Unlock()
				}
			}
		}()
	}
	for _, t := range targets {
		work <- t
	}
	close(work)
	wg.Wait()
	return results
}

func (e *Engine) fingerprintUDPOne(ctx context.Context, t Target) *Result {
	addr := net.JoinHostPort(t.IP, strconv.Itoa(t.Port))

	probes := e.orderUDPProbes(t.Port)
	for _, sp := range probes {
		if ctx.Err() != nil {
			return nil
		}
		conn, err := net.DialTimeout("udp", addr, e.timeout)
		if err != nil {
			continue
		}

		waitTimeout := sp.WaitDuration()
		if e.timeout > 0 && e.timeout < waitTimeout {
			waitTimeout = e.timeout
		}

		if len(sp.Data) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(e.timeout))
			_, err = conn.Write(sp.Data)
			if err != nil {
				conn.Close()
				continue
			}
		}

		_ = conn.SetReadDeadline(time.Now().Add(waitTimeout))
		buf := make([]byte, 65535)
		n, readErr := conn.Read(buf)
		conn.Close()

		if n == 0 || readErr != nil {
			continue
		}

		if result := e.tryMatches(sp.Matches, buf[:n]); result != nil {
			return matchResultToResult(result, false, "")
		}
	}
	return nil
}

func (e *Engine) orderUDPProbes(targetPort int) []*ServiceProbe {
	var hinted, fallback []*ServiceProbe
	for _, sp := range e.db.Probes {
		if sp.Protocol != "UDP" {
			continue
		}
		if sp.Rarity > e.intensityMax {
			continue
		}
		if sp.Ports != nil && sp.Ports.Contains(targetPort) {
			hinted = append(hinted, sp)
		} else if !e.fastMode {
			fallback = append(fallback, sp)
		}
	}
	sort.SliceStable(hinted, func(i, j int) bool {
		return hinted[i].Rarity < hinted[j].Rarity
	})
	sort.SliceStable(fallback, func(i, j int) bool {
		return fallback[i].Rarity < fallback[j].Rarity
	})
	return append(hinted, fallback...)
}

func (e *Engine) findProbe(name string) *ServiceProbe {
	for _, sp := range e.db.Probes {
		if strings.EqualFold(sp.Name, name) {
			return sp
		}
	}
	return nil
}

func matchResultToResult(mr *MatchResult, isTLS bool, banner string) *Result {
	return &Result{
		Name:       mr.Service,
		Product:    mr.Product,
		Version:    mr.Version,
		ExtraInfo:  mr.Info,
		OSType:     mr.OS,
		DeviceType: mr.DeviceType,
		Banner:     banner,
		TLS:        isTLS,
		CPEs:       mr.CPEs,
	}
}
