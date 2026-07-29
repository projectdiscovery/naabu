package runner

import "time"

// timingPreset bundles the tuning knobs a timing template controls.
type timingPreset struct {
	rate    int
	retries int
	timeout time.Duration
	warmup  int
	threads int
}

// timingTemplates map nmap-style -T levels (0 paranoid .. 5 insane) to naabu
// tuning. T3 mirrors naabu's historical defaults so the default behaviour is
// unchanged when no template is given.
var timingTemplates = map[int]timingPreset{
	0: {rate: 10, retries: 1, timeout: 5 * time.Second, warmup: 5, threads: 5},
	1: {rate: 100, retries: 1, timeout: 4 * time.Second, warmup: 4, threads: 10},
	2: {rate: 400, retries: 2, timeout: 3 * time.Second, warmup: 3, threads: 15},
	3: {rate: DefaultRateSynScan, retries: DefaultRetriesSynScan, timeout: DefaultPortTimeoutSynScan, warmup: defaultWarmUpTime, threads: DefaultThreadsNum},
	// timeouts stay >= 500ms: GetTimeout() floors anything below that, which
	// would otherwise silently clamp an aggressive preset back up to 1s.
	4: {rate: 10000, retries: 2, timeout: 700 * time.Millisecond, warmup: 1, threads: 50},
	5: {rate: 30000, retries: 1, timeout: 500 * time.Millisecond, warmup: 1, threads: 100},
}

// applyTimingTemplate applies the selected timing template, but only to knobs
// the user did not explicitly set - an explicitly set -rate / -retries /
// -timeout / -warm-up-time / -c always wins over the template. setFlags holds the
// long/short names the user actually provided on the CLI or via config, so a flag
// set to a value that happens to equal the compile-time default is still honored.
func (options *Options) applyTimingTemplate(setFlags map[string]struct{}) {
	preset, ok := timingTemplates[options.TimingTemplate]
	if !ok {
		return
	}
	set := func(names ...string) bool {
		for _, n := range names {
			if _, ok := setFlags[n]; ok {
				return true
			}
		}
		return false
	}
	if !set("rate") {
		options.Rate = preset.rate
	}
	if !set("retries") {
		options.Retries = preset.retries
	}
	if !set("timeout") {
		options.Timeout = preset.timeout
	}
	if !set("warm-up-time") {
		options.WarmUpTime = preset.warmup
	}
	if !set("c") {
		options.Threads = preset.threads
	}
}
