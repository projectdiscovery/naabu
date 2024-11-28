package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTCPSequencer(t *testing.T) {
	tcpSequencer := NewTCPSequencer()
	// tcp sequencer should be uint32 incremental
	for i := 0; i < 50000; i++ {
		actual := tcpSequencer.Next()
		assert.Equal(t, uint32(i), actual)
	}
}
