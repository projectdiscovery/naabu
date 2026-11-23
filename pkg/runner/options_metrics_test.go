package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnableMetricsIfPortSet(t *testing.T) {
	for name, tc := range map[string]struct {
		set  map[string]struct{}
		want bool
	}{
		"default port": {set: map[string]struct{}{}, want: false},
		"long flag":    {set: map[string]struct{}{"metrics-port": {}}, want: true},
		"short flag":   {set: map[string]struct{}{"mp": {}}, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			options := &Options{}
			options.enableMetricsIfPortSet(tc.set)
			require.Equal(t, tc.want, options.EnableProgressBar)
		})
	}
}
