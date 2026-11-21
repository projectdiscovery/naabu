package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLossWarnings(t *testing.T) {
	t.Run("a clean scan warns about nothing", func(t *testing.T) {
		require.Empty(t, lossWarnings(7, 7, 0))
	})

	t.Run("only the drops of this scan count", func(t *testing.T) {
		warnings := lossWarnings(10, 25, 0)
		require.Len(t, warnings, 1)
		require.Contains(t, warnings[0], "15 captured packets were dropped")
	})

	t.Run("a counter that went backwards is not a loss", func(t *testing.T) {
		require.Empty(t, lossWarnings(25, 10, 0))
	})

	t.Run("failed dials warn", func(t *testing.T) {
		warnings := lossWarnings(0, 0, 3)
		require.Len(t, warnings, 1)
		require.Contains(t, warnings[0], "3 connect probes failed")
	})

	t.Run("both losses warn", func(t *testing.T) {
		require.Len(t, lossWarnings(0, 4, 2), 2)
	})
}
