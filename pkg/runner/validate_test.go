package runner

import (
	"testing"

	"github.com/projectdiscovery/utils/errkit"
	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	options := Options{}
	assert.ErrorIs(t, errNoInputList, options.ValidateOptions())

	options.Host = []string{"target1", "target2"}
	options.Timeout = 2
	assert.EqualError(t, options.ValidateOptions(), errkit.Wrap(errZeroValue, "rate").Error())

	options.Resolvers = "aaabbbccc"
	assert.NotNil(t, options.ValidateOptions())

	options.Rate = 2
	options.ConnectPayload = "aabbcc"
	options.ScanType = SynScan
	assert.EqualError(t, options.ValidateOptions(), "connect payload can only be used with connect scan")
}
