package runner

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
)

var errMaxRuntime = errors.New("max runtime reached")

// maxRuntimeWarning reports a partial scan. Tests replace it; the pointer keeps
// that swap from racing a warning already in flight.
var maxRuntimeWarning atomic.Pointer[func(time.Duration)]

func init() {
	warn := func(d time.Duration) {
		gologger.Warning().Msgf("Max runtime %s reached, stopped sending probes: results are partial\n", d)
	}
	maxRuntimeWarning.Store(&warn)
}

// withMaxRuntime bounds only the probe-sending phase. Receivers, -sV and output
// keep the parent context, so in-flight replies are still collected and the
// partial results are written when the budget runs out.
func (r *Runner) withMaxRuntime(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.options.MaxRuntime <= 0 {
		return ctx, func() {}
	}
	ctx, cancel := context.WithTimeoutCause(ctx, r.options.MaxRuntime, errMaxRuntime)
	// Captured now, so a later test swapping the hook cannot receive this scan's warning.
	warn := maxRuntimeWarning.Load()
	context.AfterFunc(ctx, func() {
		if warn != nil && errors.Is(context.Cause(ctx), errMaxRuntime) {
			(*warn)(r.options.MaxRuntime)
		}
	})
	return ctx, cancel
}
