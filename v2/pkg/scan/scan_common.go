package scan

import (
	"net"

	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"golang.org/x/net/icmp"
)

var (
	ListenHandlers                                          []*ListenHandler
	NetworkInterface                                        string
	networkInterface                                        *net.Interface
	transportPacketSend, icmpPacketSend, ethernetPacketSend chan *PkgSend
	icmpConn4, icmpConn6                                    *icmp.PacketConn

	pkgRouter routing.Router

	ArpRequestAsync  func(ip string)
	InitScanner      func(s *Scanner) error
	NumberOfHandlers = 1
	tcpsequencer     = NewTCPSequencer()
)

type ListenHandler struct {
	Busy                                   bool
	Phase                                  Phase
	Port                                   int
	TcpConn4, UdpConn4, TcpConn6, UdpConn6 *net.IPConn
	TcpChan, UdpChan, HostDiscoveryChan    chan *PkgResult
}

func init() {
	if r, err := routing.New(); err != nil {
		panic(err)
	} else {
		pkgRouter = r
	}
}
