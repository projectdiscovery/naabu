package scan

import (
	"math"
	"sync/atomic"
)

// TCPSequencer generates linear TCP sequence numbers that wrap
// around after reaching their maximum value.
//
// According to specs, this is the correct way to approach TCP sequence
// number since linearity will be guaranteed by the wrapping around to initial 0.
type TCPSequencer struct {
	current uint32
}

// NewTCPSequencer creates a new linear tcp sequenc enumber generator
func NewTCPSequencer() *TCPSequencer {
	// Start the sequence with math.MaxUint32, which will then wrap around
	// when incremented starting the sequence with 0 as desired.
	return &TCPSequencer{current: math.MaxUint32}
}

// Next returns the next number in the sequence of tcp sequence numbers
func (t *TCPSequencer) Next() uint32 {
	value := atomic.AddUint32(&t.current, 1)
	return value
}
