package runner

import (
	"context"
	"errors"

	"github.com/projectdiscovery/gologger"
)

var errMaxRuntime = errors.New("max runtime reached")

// withMaxRuntime bounds only the probe-sending phase. Receivers, -sV and output
// keep the parent context, so in-flight replies are still collected and the
// partial results are written when the budget runs out.
func (r *Runner) withMaxRuntime(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.options.MaxRuntime <= 0 {
		return ctx, func() {}
	}
	ctx, cancel := context.WithTimeoutCause(ctx, r.options.MaxRuntime, errMaxRuntime)
	context.AfterFunc(ctx, func() {
		if errors.Is(context.Cause(ctx), errMaxRuntime) {
			gologger.Warning().Msgf("Max runtime %s reached, stopped sending probes: results are partial\n", r.options.MaxRuntime)
		}
	})
	return ctx, cancel
}
