//go:build linux || darwin

package scan

import (
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
	var zoneName string
	if s.NetworkInterface != nil {
		zoneName = s.NetworkInterface.Name
	}
	destAddr := &net.UDPAddr{IP: net.ParseIP(ip), Zone: zoneName}
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
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
}
