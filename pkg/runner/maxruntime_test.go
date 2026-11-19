package runner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithMaxRuntime(t *testing.T) {
	r := &Runner{options: &Options{}}
	ctx, stop := r.withMaxRuntime(context.Background())
	stop()
	require.NoError(t, ctx.Err(), "no limit must leave the context alone")

	r.options.MaxRuntime = 20 * time.Millisecond
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	ctx, stop = r.withMaxRuntime(parent)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("scan context must expire after max runtime")
	}
	require.ErrorIs(t, context.Cause(ctx), errMaxRuntime)
	require.NoError(t, parent.Err(), "receivers and -sV keep the parent context")
}
