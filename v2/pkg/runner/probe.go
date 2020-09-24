package runner

import (
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"go.uber.org/ratelimit"
)

func (r *Runner) pingprobesasync(ip string) {
	r.scanner.EnqueueICMP(ip, scan.ICMPECHOREQUEST)
	r.scanner.EnqueueICMP(ip, scan.ICMPTIMESTAMPREQUEST)
}

func (r *Runner) synprobesasync(ip string) {
	for p := range r.scanner.SynProbesPorts {
		r.scanner.EnqueueTCP(ip, p, scan.SYN)
	}
}

func (r *Runner) ackprobesasync(ip string) {
	for p := range r.scanner.AckProbesPorts {
		r.scanner.EnqueueTCP(ip, p, scan.ACK)
	}
}

func (r *Runner) ProbeOrSkip() {
	if r.options.NoProbe {
		return
	}
	// root is required
	if !isRoot() {
		return
	}

	limiter := ratelimit.New(r.options.Rate)
	for ip := range r.scanner.Targets {
		limiter.Take()
		r.pingprobesasync(ip)
		r.synprobesasync(ip)
		r.ackprobesasync(ip)
	}
}
