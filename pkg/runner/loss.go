package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

// warnPossibleLoss flags a scan whose results may miss open ports because
// replies were lost on this machine. Without it the loss is silent: a dropped
// SYN-ACK or a failed dial reads the same as a closed port.
func (r *Runner) warnPossibleLoss(dropsBefore uint64) {
	if drops := scan.CaptureDrops(); drops > dropsBefore {
		gologger.Warning().Msgf("%d captured packets were dropped before naabu could read them: results may be incomplete, try a lower -rate\n", drops-dropsBefore)
	}
	if failed := r.scanner.LocalDialFailures.Load(); failed > 0 {
		gologger.Warning().Msgf("%d connect probes failed because this host ran out of sockets or source ports: results may be incomplete, try a lower -rate\n", failed)
	}
}
