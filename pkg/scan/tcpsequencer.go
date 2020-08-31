package scan

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

type TCPSequencer struct {
	sync.RWMutex
	current int
}

func NewTCPSequencer() *TCPSequencer {
	rand.Seed(time.Now().UnixNano())
	return &TCPSequencer{current: 1000000000 + rand.Intn(math.MaxInt32)}
}

func (t *TCPSequencer) One() int {
	t.Lock()
	t.current++
	t.Unlock()
	return t.current
}
