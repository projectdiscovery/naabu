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

	for i := 0; i < 5; i++ {
		ch <- &PkgSend{ip: "192.168.1.1", flag: Arp}
	}

	oldChan := ethernetPacketSend
	ethernetPacketSend = ch

	done := make(chan struct{})
	go func() {
		EthernetWriteWorker()
		close(done)
	}()

	assert.Eventually(t, func() bool {
		return called.Load() == 5
	}, 2*time.Second, 10*time.Millisecond, "EthernetWriteWorker should have consumed all 5 ARP packets")

	close(ch)
	<-done

	ethernetPacketSend = oldChan
	ArpRequestAsync = origArp
}

func TestEthernetWriteWorkerDoesNotBlock(t *testing.T) {
	ch := make(chan *PkgSend, packetSendSize)

	origArp := ArpRequestAsync
	ArpRequestAsync = func(ip string) {}

	oldChan := ethernetPacketSend
	ethernetPacketSend = ch

	workerDone := make(chan struct{})
	go func() {
		EthernetWriteWorker()
		close(workerDone)
	}()

	sendDone := make(chan struct{})
	go func() {
		for i := 0; i < packetSendSize+100; i++ {
			ch <- &PkgSend{ip: "10.0.0.1", flag: Arp}
		}
		close(sendDone)
	}()

	select {
	case <-sendDone:
	case <-time.After(5 * time.Second):
		t.Fatal("EnqueueEthernet blocked — EthernetWriteWorker is not draining the channel")
	}

	close(ch)
	<-workerDone

	ethernetPacketSend = oldChan
	ArpRequestAsync = origArp
}
