package scan

import (
	"net"

	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"golang.org/x/net/icmp"
)

var (
	NetworkInterface                                        string
	tcpChan, udpChan, hostDiscoveryChan                     chan *PkgResult
	tcpConn4, udpConn4, tcpConn6, udpConn6                  *net.IPConn
	transportPacketSend, icmpPacketSend, ethernetPacketSend chan *PkgSend
	icmpConn4, icmpConn6                                    *icmp.PacketConn

	pkgRouter  routing.Router
	ListenPort int

	TransportReadWorkerPCAP func(s *Scanner)
	ArpRequestAsync         func(s *Scanner, ip string)
)

func init() {
	if r, err := routing.New(); err != nil {
		panic(err)
	} else {
		pkgRouter = r
	}
}
