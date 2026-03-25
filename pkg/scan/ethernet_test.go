package scan

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEthernetWriteWorkerConsumesPackets(t *testing.T) {
	ch := make(chan *PkgSend, 10)

	var called atomic.Int32
	origArp := ArpRequestAsync
	ArpRequestAsync = func(ip string) {
		called.Add(1)
	}

	go EthernetWriteWorker()

	for i := 0; i < 5; i++ {
		ch <- &PkgSend{ip: "192.168.1.1", flag: Arp}
	}

	// swap the channel so EthernetWriteWorker reads from ours
	oldChan := ethernetPacketSend
	ethernetPacketSend = ch
	defer func() { ethernetPacketSend = oldChan }()

	go EthernetWriteWorker()

	assert.Eventually(t, func() bool {
		return called.Load() == 5
	}, 2*time.Second, 10*time.Millisecond, "EthernetWriteWorker should have consumed all 5 ARP packets")

	close(ch)
	// wait for goroutine to fully exit before restoring
	time.Sleep(50 * time.Millisecond)
	ArpRequestAsync = origArp
}

func TestEthernetWriteWorkerDoesNotBlock(t *testing.T) {
	ch := make(chan *PkgSend, packetSendSize)

	origArp := ArpRequestAsync
	ArpRequestAsync = func(ip string) {}

	oldChan := ethernetPacketSend
	ethernetPacketSend = ch
	defer func() { ethernetPacketSend = oldChan }()

	go EthernetWriteWorker()

	done := make(chan struct{})
	go func() {
		for i := 0; i < packetSendSize+100; i++ {
			ch <- &PkgSend{ip: "10.0.0.1", flag: Arp}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("EnqueueEthernet blocked — EthernetWriteWorker is not draining the channel")
	}

	close(ch)
	// wait for goroutine to fully exit before restoring
	time.Sleep(50 * time.Millisecond)
	ArpRequestAsync = origArp
}
