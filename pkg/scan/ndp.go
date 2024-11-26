//go:build linux || darwin

package scan

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// PingNdpRequestAsync asynchronous to the target ip address
func PingNdpRequestAsync(ip string) {
	networkInterface, _, _, err := PkgRouter.Route(net.ParseIP(ip))
	if networkInterface == nil {
		err = errors.New("Could not send PingNdp Request packet to " + ip + ": no interface with outbound source found")
	}
	if err != nil {
		gologger.Debug().Msgf("%s\n", err)
		return
	}
	destAddr := &net.UDPAddr{IP: net.ParseIP(ip), Zone: networkInterface.Name}
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
	_, err = icmpConn6.WriteTo(data, destAddr)
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
}
