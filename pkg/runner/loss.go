package runner

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
)

// lossWarnings returns the warnings for a scan whose results may miss open
// ports because replies were lost on this machine. dropsBefore and dropsNow are
// the cumulative capture drops at the start and the end of the scan.
func lossWarnings(dropsBefore, dropsNow, dialFailures uint64) []string {
	var warnings []string
	if dropsNow > dropsBefore {
		warnings = append(warnings, fmt.Sprintf("%d captured packets were dropped before naabu could read them: results may be incomplete, try a lower -rate\n", dropsNow-dropsBefore))
	}
	if dialFailures > 0 {
		warnings = append(warnings, fmt.Sprintf("%d connect probes failed because this host ran out of sockets or source ports: results may be incomplete, try a lower -rate\n", dialFailures))
	}
	return warnings
}

// warnPossibleLoss flags a scan whose results may miss open ports because
// replies were lost on this machine. Without it the loss is silent: a dropped
// SYN-ACK or a failed dial reads the same as a closed port.
func (r *Runner) warnPossibleLoss(dropsBefore uint64) {
	for _, warning := range lossWarnings(dropsBefore, scan.CaptureDrops(), r.scanner.LocalDialFailures.Load()) {
		gologger.Warning().Msg(warning)
	}
}
