package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// IPv6 and UDP probes in the fast scan must spend the SYN pacer's budget.
// Falling back to the general limiter gives them a second, independent rate.
func TestRawWaitSharesTheFastPacer(t *testing.T) {
	p := newPacer(1000)
	p.budget = 3

	rawWait(p, func() { t.Fatal("raw probe used the limiter") })()
	require.Equal(t, int64(2), p.budget)

	called := false
	rawWait(nil, func() { called = true })()
	require.True(t, called)
}
