package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_AddTarget(t *testing.T) {
	r := &Runner{}

	// IPV6 Compressed should generate a warning
	err := r.AddTarget("::ffff:c0a8:101")
	require.NotNil(t, err, "compressed ipv6 incorrectly parsed")

	// IPV6 Expanded (Shortened)
	err = r.AddTarget("0:0:0:0:0:ffff:c0a8:0101")
	require.NotNil(t, err, "expanded shortened ipv6 incorrectly parsed")

	// IPV6 Expanded
	err = r.AddTarget("0000:0000:0000:0000:0000:ffff:c0a8:0101")
	require.NotNil(t, err, "fully expanded ipv6 incorrectly parsed")

}
