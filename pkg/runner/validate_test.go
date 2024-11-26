package runner

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestOptions(t *testing.T) {
	options := Options{}
	assert.ErrorIs(t, errNoInputList, options.ValidateOptions())

	options.Host = []string{"target1", "target2"}
	assert.EqualError(t, options.ValidateOptions(), errors.Wrap(errZeroValue, "timeout").Error())

	options.Timeout = 2
	assert.EqualError(t, options.ValidateOptions(), errors.Wrap(errZeroValue, "rate").Error())

	options.Resolvers = "aaabbbccc"
	assert.NotNil(t, options.ValidateOptions())
}
