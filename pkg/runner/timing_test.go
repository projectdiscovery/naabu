package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func defaultTimedOptions() *Options {
	return &Options{
		Rate:       DefaultRateSynScan,
		Retries:    DefaultRetriesSynScan,
		Timeout:    DefaultPortTimeoutSynScan,
		WarmUpTime: defaultWarmUpTime,
		Threads:    DefaultThreadsNum,
	}
}

func TestTimingTemplateT3IsNoOp(t *testing.T) {
	o := defaultTimedOptions()
	o.TimingTemplate = 3
	o.applyTimingTemplate(nil)
	require.Equal(t, DefaultRateSynScan, o.Rate)
	require.Equal(t, DefaultRetriesSynScan, o.Retries)
	require.Equal(t, DefaultPortTimeoutSynScan, o.Timeout)
	require.Equal(t, defaultWarmUpTime, o.WarmUpTime)
	require.Equal(t, DefaultThreadsNum, o.Threads)
}

func TestTimingTemplateAggressiveOverridesDefaults(t *testing.T) {
	o := defaultTimedOptions()
	o.TimingTemplate = 5
	o.applyTimingTemplate(nil)
	require.Equal(t, 30000, o.Rate)
	require.Equal(t, 1, o.Retries)
	require.Equal(t, 500*time.Millisecond, o.Timeout)
	require.Equal(t, 1, o.WarmUpTime)
	require.Equal(t, 100, o.Threads)
}

// TestTimingTemplatesNotClampedByGetTimeout guards against presets whose
// timeout falls below the GetTimeout() floor and would be silently raised.
func TestTimingTemplatesNotClampedByGetTimeout(t *testing.T) {
	for level := 0; level <= 5; level++ {
		o := defaultTimedOptions()
		o.ScanType = SynScan
		o.TimingTemplate = level
		o.applyTimingTemplate(nil)
		require.Equalf(t, o.Timeout, o.GetTimeout(),
			"template T%d timeout %s must survive the GetTimeout floor", level, o.Timeout)
	}
}

func TestTimingTemplateRespectsExplicitFlags(t *testing.T) {
	o := defaultTimedOptions()
	o.TimingTemplate = 5
	// User explicitly set rate and timeout to non-default values.
	o.Rate = 7777
	o.Timeout = 2 * time.Second
	o.applyTimingTemplate(map[string]struct{}{"rate": {}, "timeout": {}})
	require.Equal(t, 7777, o.Rate, "explicit rate must win over template")
	require.Equal(t, 2*time.Second, o.Timeout, "explicit timeout must win over template")
	// Knobs left at default still take the template value.
	require.Equal(t, 1, o.Retries)
	require.Equal(t, 100, o.Threads)
}

// TestTimingTemplateHonorsExplicitDefaultValue ensures a flag the user set to a
// value that happens to equal the compile-time default still wins over the
// template. The previous value-comparison logic silently overrode it.
func TestTimingTemplateHonorsExplicitDefaultValue(t *testing.T) {
	o := defaultTimedOptions()
	o.TimingTemplate = 5
	// User explicitly passed -c <DefaultThreadsNum>; it must not be bumped to 100.
	o.Threads = DefaultThreadsNum
	o.applyTimingTemplate(map[string]struct{}{"c": {}})
	require.Equal(t, DefaultThreadsNum, o.Threads, "explicit -c equal to default must win over template")
	// Knobs the user did not set still take the template value.
	require.Equal(t, 30000, o.Rate)
}

func TestTimingTemplateOutOfRangeIsNoOp(t *testing.T) {
	o := defaultTimedOptions()
	o.TimingTemplate = 9
	o.applyTimingTemplate(nil)
	require.Equal(t, DefaultRateSynScan, o.Rate)
	require.Equal(t, DefaultThreadsNum, o.Threads)
}
