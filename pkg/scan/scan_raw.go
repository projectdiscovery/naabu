//go:build linux || darwin || windows

package scan

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Mzack9999/gopacket"
	"github.com/Mzack9999/gopacket/layers"
	"github.com/Mzack9999/gopacket/pcap"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	iputil "github.com/projectdiscovery/utils/ip"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	handlers *Handlers
)

// Handlers contains the list of pcap handlers
type Handlers struct {
	InterfaceHandle   map[string]*pcap.Handle
	TransportActive   []*pcap.Handle
	LoopbackHandlers  []*pcap.Handle
	TransportInactive []*pcap.InactiveHandle
	EthernetActive    []*pcap.Handle
	EthernetInactive  []*pcap.InactiveHandle
}

func init() {
	// Only wire the indirection used by Acquire/Release in scan_common.go
	// (which is not build-constrained, so it cannot reference these raw-socket
	// symbols directly). No sockets, goroutines or pcap handles are created at
	// import time anymore: everything is brought up lazily on the first SYN
	// scan via ensureRawInfra.
	buildHandlerFn = buildListenHandler
	ensureRawInfraFn = ensureRawInfra
}

var (
	rawInfraOnce sync.Once
	rawInfraOK   bool
)

// ensureRawInfra lazily brings up the process-wide raw scan infrastructure
// (icmp sockets, pcap capture, write/read workers) the first time a privileged
// SYN scan needs it. Handlers are still created on demand per scan; the capture
// filter is port-independent (flag based) so newly acquired handlers require no
// filter changes and any number of scans can run in parallel.
func ensureRawInfra() bool {
	rawInfraOnce.Do(func() {
		if PkgRouter == nil || !privileges.IsPrivileged {
			return
		}

		transportPacketSend = make(chan *PkgSend, packetSendSize)

		var err error
		icmpConn4, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			gologger.Debug().Msgf("could not setup ip4:icmp: %s", err)
		}
		icmpConn6, err = icmp.ListenPacket("ip6:icmp", "::")
		if err != nil {
			gologger.Debug().Msgf("could not setup ip6:icmp: %s", err)
		}

		icmpPacketSend = make(chan *PkgSend, packetSendSize)
		ethernetPacketSend = make(chan *PkgSend, packetSendSize)

		handlers = &Handlers{
			InterfaceHandle: make(map[string]*pcap.Handle),
		}
		if err := SetupHandlers(); err != nil {
			gologger.Error().Msgf("could not setup handlers: %s\n", err)
			return
		}
		if len(handlers.TransportActive)+len(handlers.LoopbackHandlers) == 0 {
			gologger.Error().Msgf("could not open any pcap capture interface (is Npcap/libpcap installed?)")
			return
		}
		go TransportReadWorker()
		go TransportWriteWorker()
		// One reader per icmp family routes replies to whichever handlers are
		// currently in the host-discovery phase. A single shared reader avoids
		// multiple per-scan handlers stealing each other's replies off the
		// shared conn.
		go icmpReadWorker4()
		go icmpReadWorker6()
		// Spawn multiple ICMP write workers: ranging over icmpPacketSend from
		// several goroutines is safe, and concurrent WriteTo on the shared
		// icmpConn4/icmpConn6 is supported by net.PacketConn. With one worker
		// the per-host retry-sleep inside PingIcmp*RequestAsync serialises the
		// whole scan; fanning out lets those sleeps overlap. See #1672.
		for i := 0; i < icmpWriteWorkers; i++ {
			go ICMPWriteWorker()
		}
		go EthernetWriteWorker(ethernetPacketSend)
		rawInfraOK = true
	})
	return rawInfraOK
}

func buildListenHandler() (*ListenHandler, error) {
	listenHandler := NewListenHandler()
	if port, err := freeport.GetFreeTCPPort(""); err != nil {
		return nil, fmt.Errorf("could not setup get free port: %s", err)
	} else {
		listenHandler.Port = port.Port
	}

	listenHandler.TcpChan = make(chan *PkgResult, chanSize)
	listenHandler.UdpChan = make(chan *PkgResult, chanSize)
	listenHandler.HostDiscoveryChan = make(chan *PkgResult, chanSize)

	var err error
	listenHandler.TcpConn4, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		// Windows forbids bind() on raw IPPROTO_TCP sockets. SYN scans there
		// use Npcap for both inject and capture instead of ListenIP.
		if runtime.GOOS == "windows" {
			gologger.Debug().Msgf("ip4:tcp raw socket unavailable (%s); using npcap for SYN transmit", err)
		} else {
			return nil, fmt.Errorf("could not setup ip4:tcp: %s", err)
		}
	}
	listenHandler.UdpConn4, err = net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP("0.0.0.0")})
	if err != nil {
		return nil, fmt.Errorf("could not setup ip4:udp: %s", err)
	}

	listenHandler.TcpConn6, _ = net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP("::")})

	listenHandler.UdpConn6, _ = net.ListenIP("ip6:udp", &net.IPAddr{IP: net.ParseIP("::")})

	// icmp replies are handled by the process-global icmpReadWorker4/6; these
	// per-handler workers only drain the raw transport sockets so their kernel
	// receive buffers do not fill. They exit when Release closes the conns.
	if listenHandler.TcpConn4 != nil {
		go listenHandler.TcpReadWorker4()
	}
	go listenHandler.TcpReadWorker6()
	if listenHandler.UdpConn4 != nil {
		go listenHandler.UdpReadWorker4()
	}
	go listenHandler.UdpReadWorker6()
	return listenHandler, nil
}

// ICMPWriteWorker writes packet to the network layer
func ICMPWriteWorker() {
	for pkg := range icmpPacketSend {
		switch pkg.flag {
		case IcmpEchoRequest:
			PingIcmpEchoRequestAsync(pkg.ip)
		case IcmpTimestampRequest:
			PingIcmpTimestampRequestAsync(pkg.ip)
		case IcmpAddressMaskRequest:
			PingIcmpAddressMaskRequestAsync(pkg.ip)
		case Ndp:
			PingNdpRequestAsync(pkg.ip)
		}
	}
}

// EthernetWriteWorker writes packet to the network layer
func EthernetWriteWorker(ch <-chan *PkgSend) {
	for pkg := range ch {
		switch pkg.flag {
		case Arp:
			ArpRequestAsync(pkg.ip)
		}
	}
}

// TCPWriteWorker that sends out TCP|UDP packets
func TransportWriteWorker() {
	for pkg := range transportPacketSend {
		SendAsyncPkg(pkg.ListenHandler, pkg.ip, pkg.port, pkg.flag)
	}
}

// SendAsyncPkg sends a single packet to a port
func SendAsyncPkg(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	isIP4 := iputil.IsIPv4(ip)
	isIP6 := iputil.IsIPv6(ip)
	isTCP := p.Protocol == protocol.TCP
	isUDP := p.Protocol == protocol.UDP
	switch {
	case isIP4 && isTCP:
		sendAsyncTCP4(listenHandler, ip, p, pkgFlag)
	case isIP4 && isUDP:
		sendAsyncUDP4(listenHandler, ip, p, pkgFlag)
	case isIP6 && isTCP:
		sendAsyncTCP6(listenHandler, ip, p, pkgFlag)
	case isIP6 && isUDP:
		sendAsyncUDP6(listenHandler, ip, p, pkgFlag)
	}
}

func sendAsyncTCP4(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	var eth layers.Ethernet
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}

	hasSourceIp := listenHandler.SourceIp4 != nil
	// Windows cannot open raw IPPROTO_TCP sockets; always send via Npcap L2.
	usePcap := listenHandler.TcpConn4 == nil || (hasSourceIp && listenHandler.SourceHW != nil)
	var iface *net.Interface
	if hasSourceIp && listenHandler.SourceHW != nil {
		// NOTE(dwisiswant0): Only attempt to use ethernet framing if we have
		// both source IP and HW.
		itf, gateway, _, err := PkgRouter.RouteWithSrc(listenHandler.SourceHW, listenHandler.SourceIp4, ip4.DstIP)
		if err != nil {
			gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
			return
		}
		dstMAC, err := linkDestinationMAC(gateway, ip4.DstIP)
		if err != nil {
			gologger.Debug().Msgf("could not find gateway MAC %s:%d: %s\n", ip, p.Port, err)
			return
		}

		eth = layers.Ethernet{
			EthernetType: layers.EthernetTypeIPv4,
			SrcMAC:       listenHandler.SourceHW,
			DstMAC:       dstMAC,
		}
		ip4.SrcIP = listenHandler.SourceIp4
		iface = itf
	} else if usePcap {
		var itf *net.Interface
		var gateway, sourceIP net.IP
		var err error
		if hasSourceIp {
			// Keep the caller-configured source IP; only resolve iface/gateway.
			itf, gateway, _, err = PkgRouter.RouteWithSrc(listenHandler.SourceHW, listenHandler.SourceIp4, ip4.DstIP)
			sourceIP = listenHandler.SourceIp4
		} else {
			itf, gateway, sourceIP, err = PkgRouter.Route(ip4.DstIP)
		}
		if err != nil {
			gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
			return
		} else if sourceIP == nil || itf == nil {
			gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
			return
		}
		srcHW := listenHandler.SourceHW
		if len(srcHW) == 0 {
			srcHW = itf.HardwareAddr
		}
		if len(srcHW) == 0 {
			gologger.Debug().Msgf("could not find source MAC for %s:%d\n", ip, p.Port)
			return
		}
		dstMAC, err := linkDestinationMAC(gateway, ip4.DstIP)
		if err != nil {
			gologger.Debug().Msgf("could not find gateway MAC %s:%d: %s\n", ip, p.Port, err)
			return
		}
		eth = layers.Ethernet{
			EthernetType: layers.EthernetTypeIPv4,
			SrcMAC:       srcHW,
			DstMAC:       dstMAC,
		}
		ip4.SrcIP = sourceIP
		iface = itf
	} else {
		if hasSourceIp {
			// NOTE(dwisiswant0): We have source IP but no HW, so use it
			// regular raw socket
			ip4.SrcIP = listenHandler.SourceIp4
		} else {
			_, _, sourceIP, err := PkgRouter.Route(ip4.DstIP)
			if err != nil {
				gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
				return
			} else if sourceIP == nil {
				gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
				return
			}
			ip4.SrcIP = sourceIP
		}
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	seq := tcpsequencer.Next()
	if pkgFlag == Syn {
		// SYN cookie: lets the receive path verify the returning SYN-ACK.
		seq = SynCookie(ip4.DstIP, uint16(p.Port), uint16(listenHandler.Port))
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(listenHandler.Port),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     seq,
		Options: []layers.TCPOption{tcpOption},
	}

	switch pkgFlag {
	case Syn:
		tcp.SYN = true
	case Ack:
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	}

	if usePcap && iface != nil && len(eth.DstMAC) > 0 {
		err = sendWithHandler(ip, iface, &eth, &ip4, &tcp)
	} else {
		if listenHandler.TcpConn4 == nil {
			gologger.Debug().Msgf("TcpConn4 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.TcpConn4, &tcp)
	}

	if err != nil {
		gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
	}
}

// linkDestinationMAC resolves the next-hop Ethernet address: the gateway when
// routed, otherwise the on-link destination itself.
func linkDestinationMAC(gateway, dst net.IP) (net.HardwareAddr, error) {
	target := gateway
	if target == nil || target.IsUnspecified() {
		target = dst
	}
	if target == nil {
		return nil, errors.New("no link destination")
	}
	return routing.GetGatewayMac(target.String())
}

func sendAsyncUDP4(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, sourceIP, err := PkgRouter.Route(ip4.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
		return
	}

	if listenHandler.SourceIp4 != nil {
		ip4.SrcIP = listenHandler.SourceIp4
	} else {
		ip4.SrcIP = sourceIP
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(listenHandler.Port),
		DstPort: layers.UDPPort(p.Port),
	}

	err = udp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		if listenHandler.UdpConn4 == nil {
			gologger.Debug().Msgf("UdpConn4 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.UdpConn4, listenHandler.udpLayersWithProbe(&udp, p.Port)...)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

func sendAsyncTCP6(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolTCP,
	}

	_, _, sourceIP, err := PkgRouter.Route(ip6.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
		return
	}

	if listenHandler.SourceIP6 != nil {
		ip6.SrcIP = listenHandler.SourceIP6
	} else {
		ip6.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	seq := tcpsequencer.Next()
	if pkgFlag == Syn {
		// SYN cookie: lets the receive path verify the returning SYN-ACK.
		seq = SynCookie(ip6.DstIP, uint16(p.Port), uint16(listenHandler.Port))
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(listenHandler.Port),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     seq,
		Options: []layers.TCPOption{tcpOption},
	}

	switch pkgFlag {
	case Syn:
		tcp.SYN = true
	case Ack:
		tcp.ACK = true
	}

	err = tcp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		if listenHandler.TcpConn6 == nil {
			gologger.Debug().Msgf("TcpConn6 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.TcpConn6, &tcp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

func sendAsyncUDP6(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolUDP,
	}

	_, _, sourceIP, err := PkgRouter.Route(ip6.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
		return
	}

	if listenHandler.SourceIP6 != nil {
		ip6.SrcIP = listenHandler.SourceIP6
	} else {
		ip6.SrcIP = sourceIP
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(listenHandler.Port),
		DstPort: layers.UDPPort(p.Port),
	}

	err = udp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		if listenHandler.UdpConn6 == nil {
			gologger.Debug().Msgf("UdpConn6 is nil, cannot send packet to %s:%d\n", ip, p.Port)
			return
		}

		err = sendWithConn(ip, listenHandler.UdpConn6, listenHandler.udpLayersWithProbe(&udp, p.Port)...)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

// dispatchHostDiscovery delivers a host-discovery result (icmp/arp reply) to
// every handler currently in the host-discovery phase. Sends are non-blocking
// so a slow or torn-down handler cannot stall the shared reader, and the
// snapshot is taken under the pool read lock so it composes with on-demand
// Acquire/Release.
func dispatchHostDiscovery(res *PkgResult) {
	listenHandlersMu.RLock()
	defer listenHandlersMu.RUnlock()
	for _, l := range ListenHandlers {
		if l.Phase != nil && l.Phase.Is(HostDiscovery) {
			select {
			case l.HostDiscoveryChan <- res:
			default:
			}
		}
	}
}

// icmpReadWorker4 reads ipv4 icmp replies from the shared conn and fans them
// out to the handlers doing host discovery.
func icmpReadWorker4() {
	if icmpConn4 == nil {
		return
	}
	data := make([]byte, 1500)
	for {
		n, addr, err := icmpConn4.ReadFrom(data)
		if err != nil {
			return
		}

		rm, err := icmp.ParseMessage(ProtocolICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeTimestampReply:
			dispatchHostDiscovery(&PkgResult{ipv4: addr.String()})
		}
	}
}

// icmpReadWorker6 reads ipv6 icmp replies from the shared conn and fans them
// out to the handlers doing host discovery.
func icmpReadWorker6() {
	if icmpConn6 == nil {
		return
	}
	data := make([]byte, 1500)
	for {
		n, addr, err := icmpConn6.ReadFrom(data)
		if err != nil {
			return
		}

		rm, err := icmp.ParseMessage(ProtocolIPv6ICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv6.ICMPTypeEchoReply:
			ip := addr.String()
			// check if it has [host]:port
			if ipSplit, _, err := net.SplitHostPort(ip); err == nil {
				ip = ipSplit
			}
			// drop zone
			if idx := strings.Index(ip, "%"); idx > 0 {
				ip = ip[:idx]
			}
			dispatchHostDiscovery(&PkgResult{ipv6: ip})
		}
	}
}

var defaultSerializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// send sends the given layers as a single packet on the network.
func sendWithConn(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	var err error

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOptions, l...); err != nil {
		return err
	}
	data := buf.Bytes()
	addr := &net.IPAddr{IP: net.ParseIP(destIP)}

	for retries := 0; retries < maxRetries; retries++ {
		_, err = conn.WriteTo(data, addr)
		if err == nil {
			return nil
		}

		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("could not send packet to %s: %s", destIP, err)
	}

	return nil
}

func sendWithHandler(destIP string, iface *net.Interface, l ...gopacket.SerializableLayer) error {
	var err error

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOptions, l...); err != nil {
		return err
	}
	data := buf.Bytes()

	// find the correct handler
	handler, ok := handlers.InterfaceHandle[iface.Name]
	if handler == nil || !ok {
		return errors.New("could not find correct pcap handler")
	}

	for retries := 0; retries < maxRetries; retries++ {
		err = handler.WritePacketData(data)
		if err == nil {
			return nil
		}

		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("could not send packet to %s: %s", destIP, err)
	}

	return nil
}

func (l *ListenHandler) TcpReadWorker4() {
	if l.TcpConn4 == nil {
		return
	}
	data := make([]byte, 4096)
	for {
		if _, _, err := l.TcpConn4.ReadFrom(data); err != nil {
			return
		}
	}
}

func (l *ListenHandler) TcpReadWorker6() {
	if l.TcpConn6 == nil {
		return
	}
	data := make([]byte, 4096)
	for {
		if _, _, err := l.TcpConn6.ReadFrom(data); err != nil {
			return
		}
	}
}

func (l *ListenHandler) UdpReadWorker4() {
	if l.UdpConn4 == nil {
		return
	}
	data := make([]byte, 4096)
	for {
		if _, _, err := l.UdpConn4.ReadFrom(data); err != nil {
			return
		}
	}
}
func (l *ListenHandler) UdpReadWorker6() {
	if l.UdpConn6 == nil {
		return
	}
	data := make([]byte, 4096)
	for {
		if _, _, err := l.UdpConn6.ReadFrom(data); err != nil {
			return
		}
	}
}

// SetupHandlerUnix on unix OS
func SetupHandlerUnix(interfaceName, bpfFilter string, protocols ...protocol.Protocol) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	pcapName := pcapDeviceForInterface(iface)

	for _, proto := range protocols {
		inactive, err := pcap.NewInactiveHandle(pcapName)
		if err != nil {
			return err
		}

		err = inactive.SetSnapLen(snaplen)
		if err != nil {
			return err
		}

		readTimeout := time.Duration(readtimeout) * time.Millisecond
		if err = inactive.SetTimeout(readTimeout); err != nil {
			CleanupHandlersUnix()
			return err
		}
		err = inactive.SetImmediateMode(true)
		if err != nil {
			return err
		}
		// Best-effort: a large capture buffer keeps reply bursts from large port
		// ranges from overflowing the kernel ring and silently dropping
		// SYN-ACKs. Failure is non-fatal; the handle keeps the OS default.
		if err = inactive.SetBufferSize(pcapBufferSize); err != nil {
			gologger.Debug().Msgf("could not set pcap buffer size on %s: %s", interfaceName, err)
		}

		switch proto {
		case protocol.TCP, protocol.UDP:
			handlers.TransportInactive = append(handlers.TransportInactive, inactive)
		case protocol.ARP:
			handlers.EthernetInactive = append(handlers.EthernetInactive, inactive)
		default:
			panic("protocol not supported")
		}

		handle, err := inactive.Activate()
		if err != nil {
			CleanupHandlersUnix()
			return err
		}

		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			return err
		}
		switch proto {
		case protocol.TCP, protocol.UDP:
			if iface.Flags&net.FlagLoopback == net.FlagLoopback {
				handlers.LoopbackHandlers = append(handlers.LoopbackHandlers, handle)
			} else {
				handlers.TransportActive = append(handlers.TransportActive, handle)
			}
			// Always key by the net.Interface name so send paths that resolve
			// routes against net.Interfaces can find the handle, even when the
			// underlying pcap device name differs (Windows Npcap).
			handlers.InterfaceHandle[iface.Name] = handle
		case protocol.ARP:
			handlers.EthernetActive = append(handlers.EthernetActive, handle)
		default:
			panic("protocol not supported")
		}
	}

	return nil
}

func TransportReadWorker() {
	var wgread sync.WaitGroup

	transportReaderCallback := func(tcp layers.TCP, udp layers.UDP, srcIP4, srcIP6 string) {
		listenHandlersMu.RLock()
		defer listenHandlersMu.RUnlock()
		for _, listenHandler := range ListenHandlers {
			// We consider only incoming packets
			tcpPortMatches := tcp.DstPort == layers.TCPPort(listenHandler.Port)
			udpPortMatches := udp.DstPort == layers.UDPPort(listenHandler.Port)
			sourcePortMatches := tcpPortMatches || udpPortMatches
			switch {
			case !sourcePortMatches:
				gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s tcp_dport=%d udp_dport=%d\n", srcIP4, srcIP6, tcp.DstPort, udp.DstPort)
			case listenHandler.Phase.Is(HostDiscovery):
				proto := protocol.TCP
				srcPort := int(tcp.SrcPort)
				if udpPortMatches {
					proto = protocol.UDP
					srcPort = int(udp.SrcPort)
				}
				listenHandler.HostDiscoveryChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: srcPort, Protocol: proto}}
			case tcpPortMatches && tcp.SYN && tcp.ACK:
				if !verifySynCookie(srcIP4, srcIP6, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.Ack) {
					gologger.Debug().Msgf("Discarding SYN-ACK with invalid cookie: ip4=%s ip6=%s port=%d\n", srcIP4, srcIP6, tcp.SrcPort)
					continue
				}
				listenHandler.TcpChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: int(tcp.SrcPort), Protocol: protocol.TCP}}
			case udpPortMatches && udp.Length > 0: // needs a better matching of udp payloads
				listenHandler.UdpChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: int(udp.SrcPort), Protocol: protocol.UDP}}
			}
		}
	}

	// In case of OSX, when we decode the data from 'loO' interface
	// always get [Ethernet] layer only.
	// with the help of data received from packetSource.Packets() we can
	// extract the high level layers like [IPv4, IPv6, TCP, UDP]
	loopBackScanCaseCallback := func(handler *pcap.Handle, wg *sync.WaitGroup) {
		defer wg.Done()
		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
		for packet := range packetSource.Packets() {
			tcp := &layers.TCP{}
			udp := &layers.UDP{}
			for _, layerType := range packet.Layers() {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					ipLayer = packet.Layer(layers.LayerTypeIPv6)
					if ipLayer == nil {
						continue
					}
				}
				var srcIP4, srcIP6 string
				if ipv4, ok := ipLayer.(*layers.IPv4); ok {
					srcIP4 = ToString(ipv4.SrcIP)
				} else if ipv6, ok := ipLayer.(*layers.IPv6); ok {
					srcIP6 = ToString(ipv6.SrcIP)
				}

				var ok bool
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, ok = tcpLayer.(*layers.TCP)
					if !ok {
						continue
					}
				}
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, ok = udpLayer.(*layers.UDP)
					if !ok {
						continue
					}
				}

				if layerType.LayerType() == layers.LayerTypeTCP || layerType.LayerType() == layers.LayerTypeUDP {
					transportReaderCallback(*tcp, *udp, srcIP4, srcIP6)
				}
			}
		}
	}

	// Loopback Readers
	for _, handler := range handlers.LoopbackHandlers {
		wgread.Add(1)
		go loopBackScanCaseCallback(handler, &wgread)
	}

	// Transport Readers (TCP|UDP)
	for _, handler := range handlers.TransportActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				ip6 layers.IPv6
				tcp layers.TCP
				udp layers.UDP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parser4Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
			parser6Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp, &udp)
			// Interfaces without MAC (TUN/TAP)
			parser4NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp)
			parser6NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers,
				parser4Mac, parser6Mac,
				parser4NoMac, parser6NoMac,
			)

			decoded := make([]gopacket.LayerType, 0, 8)

			// Read straight off the handle (zero-copy) instead of
			// gopacket.PacketSource.Packets(), which allocates a *gopacket.Packet
			// and hops through an extra goroutine+channel for every packet. On a
			// SYN scan every reply lands here, so this is the receive hot path.
			for {
				data, _, err := handler.ZeroCopyReadPacketData()
				if err != nil {
					if errors.Is(err, pcap.NextErrorTimeoutExpired) {
						continue
					}
					// EOF or a closed handle ends the reader; any other error is
					// treated as fatal to avoid spinning on a broken handle.
					return
				}
				for _, parser := range parsers {
					if err := parser.DecodeLayers(data, &decoded); err != nil {
						continue
					}
					hasTransport := false
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
							hasTransport = true
							break
						}
					}
					if !hasTransport {
						continue
					}
					// tcp/udp are reused across packets by the parser and absent
					// layers keep their previous value; forward only the transport
					// layer actually present in this packet so the callback can't
					// match on a stale port from an earlier packet.
					var srcIP4, srcIP6 string
					var tcpForCb layers.TCP
					var udpForCb layers.UDP
					for _, layerType := range decoded {
						switch layerType {
						case layers.LayerTypeIPv4:
							srcIP4 = ToString(ip4.SrcIP)
						case layers.LayerTypeIPv6:
							srcIP6 = ToString(ip6.SrcIP)
						case layers.LayerTypeTCP:
							tcpForCb = tcp
						case layers.LayerTypeUDP:
							udpForCb = udp
						}
					}
					transportReaderCallback(tcpForCb, udpForCb, srcIP4, srcIP6)
					break
				}
			}
		}(handler)
	}

	// Ethernet Readers
	for _, handler := range handlers.EthernetActive {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				arp layers.ARP
			)

			parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp)
			parser4.IgnoreUnsupported = true
			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parser4)

			decoded := []gopacket.LayerType{}

			packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
			packetSource.DecodeOptions = gopacket.DecodeOptions{
				Lazy:   true,
				NoCopy: true,
			}
			for packet := range packetSource.Packets() {
				data := packet.Data()
				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeARP {
							// check if the packet was sent out
							isReply := arp.Operation == layers.ARPReply
							var sourceMacIsInterfaceMac bool
							if networkInterface != nil {
								sourceMacIsInterfaceMac = bytes.Equal([]byte(networkInterface.HardwareAddr), arp.SourceHwAddress)
							}
							isOutgoingPacket := !isReply || sourceMacIsInterfaceMac
							if isOutgoingPacket {
								continue
							}
							srcIP4 := net.IP(arp.SourceProtAddress)
							srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()

							dispatchHostDiscovery(&PkgResult{ipv4: ToString(srcIP4), mac: srcMAC})
						}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// CleanupHandlers for all interfaces
func CleanupHandlersUnix() {
	allActive := append(handlers.TransportActive, handlers.EthernetActive...)
	allActive = append(allActive, handlers.LoopbackHandlers...)
	for _, handler := range allActive {
		handler.Close()
	}
	allInactive := append(handlers.TransportInactive, handlers.EthernetInactive...)
	for _, inactiveHandler := range allInactive {
		inactiveHandler.CleanUp()
	}
}

func SetupHandlers() error {
	if NetworkInterface != "" {
		return SetupHandler(NetworkInterface)
	}

	// listen on all interfaces manually
	// unfortunately s.SetupHandler("any") causes ip4 to be ignored
	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		isInterfaceDown := itf.Flags&net.FlagUp == 0
		if isInterfaceDown {
			continue
		}
		if err := SetupHandler(itf.Name); err != nil {
			gologger.Warning().Msgf("Error on interface %s: %s", itf.Name, err)
		}
	}

	return nil
}

func SetupHandler(interfaceName string) error {
	// Port-independent capture. Handlers are created on demand, so their source
	// ports cannot be baked into the filter (and runtime SetBPFFilter is not
	// safe against the live reader). Capture inbound TCP that carries ACK or
	// RST - SYN-ACK for open ports, RST/RST-ACK for closed ports and TCP host
	// discovery - plus UDP, while excluding our own outgoing pure-SYN probes.
	// The reader still routes each packet to the owning handler by destination
	// port, so any number of handlers share this one filter.
	bpfFilter := "(tcp and (tcp[tcpflags] & (tcp-ack|tcp-rst) != 0)) or udp"
	err := SetupHandlerUnix(interfaceName, bpfFilter, protocol.TCP)
	if err != nil {
		return err
	}
	// arp filter should be improved with source mac
	// https://stackoverflow.com/questions/40196549/bpf-expression-to-capture-only-arp-reply-packets
	// (arp[6:2] = 2) and dst host host and ether dst mac
	bpfFilter = "arp"
	err = SetupHandlerUnix(interfaceName, bpfFilter, protocol.ARP)
	if err != nil {
		return err
	}

	return nil
}

// ACKPort sends an ACK packet to a port
func ACKPort(listenHandler *ListenHandler, dstIP string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return false, err
	}

	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}

	_, _, sourceIP, err := PkgRouter.Route(ip4.DstIP)
	if err != nil {
		return false, err
	}

	if listenHandler.SourceIp4 != nil {
		ip4.SrcIP = listenHandler.SourceIp4
	} else {
		ip4.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort.Port),
		DstPort: layers.TCPPort(port),
		ACK:     true,
		Window:  1024,
		Seq:     tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return false, err
	}

	err = sendWithConn(dstIP, conn, &tcp)
	if err != nil {
		return false, err
	}

	data := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(data)
		if err != nil {
			break
		}

		// not matching ip
		if addr.String() != dstIP {
			gologger.Debug().Msgf("Discarding TCP packet from non target ip %s for %s\n", dstIP, addr.String())
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// We consider only incoming packets
			if tcp.DstPort != layers.TCPPort(rawPort.Port) {
				gologger.Debug().Msgf("Discarding TCP packet from %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, dstIP, rawPort.Port)
				continue
			} else if tcp.RST {
				gologger.Debug().Msgf("Accepting RST packet from %s:%d\n", addr.String(), tcp.DstPort)
				return true, nil
			}
		}
	}

	return false, nil
}
