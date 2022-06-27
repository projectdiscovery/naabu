//go:build linux || darwin

package scan

import (
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func init() {
	pingNdpRequestAsyncCallback = PingNdpRequestAsync
}

// PingNdpRequestAsync asynchronous to the target ip address
func PingNdpRequestAsync(s *Scanner, ip string) {
	destAddr := &net.UDPAddr{IP: net.ParseIP(ip), Zone: s.NetworkInterface.Name}
	m := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return
	}
	retries := 0
send:
	if retries >= maxRetries {
		return
	}
	_, err = s.icmpPacketListener6.WriteTo(data, destAddr)
	log.Println(err)
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
}
