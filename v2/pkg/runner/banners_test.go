package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShowNetworkInterfaces(t *testing.T) {
	// non root users should be able to list interfaces
	assert.Nil(t, showNetworkInterfaces())
}
