//go:build linux || darwin

package scan

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
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
	TransportActive   []*pcap.Handle
	LoopbackHandlers  []*pcap.Handle
	TransportInactive []*pcap.InactiveHandle
	EthernetActive    []*pcap.Handle
	EthernetInactive  []*pcap.InactiveHandle
}

func init() {
	if !privileges.IsPrivileged {
		return
	}

	transportPacketSend = make(chan *PkgSend, packetSendSize)

	var err error
	icmpConn4, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		panic(err)
	}

	icmpConn6, err = icmp.ListenPacket("ip6:icmp", "::")
	if err != nil {
		gologger.Error().Msgf("could not setup ip6:icmp: %s", err)
	}

	icmpPacketSend = make(chan *PkgSend, packetSendSize)
	ethernetPacketSend = make(chan *PkgSend, packetSendSize)

	// pre-reserve up to 10 ports
	for i := 0; i < NumberOfHandlers; i++ {
		var listenHandler ListenHandler
		if port, err := freeport.GetFreeTCPPort(""); err != nil {
			panic(err)
		} else {
			listenHandler.Port = port.Port
		}

		listenHandler.TcpChan = make(chan *PkgResult, chanSize)
		listenHandler.UdpChan = make(chan *PkgResult, chanSize)
		listenHandler.HostDiscoveryChan = make(chan *PkgResult, chanSize)

		var err error
		listenHandler.TcpConn4, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", listenHandler.Port))})
		if err != nil {
			panic(err)
		}
		listenHandler.UdpConn4, err = net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", listenHandler.Port))})
		if err != nil {
			panic(err)
		}

		listenHandler.TcpConn6, err = net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", listenHandler.Port))})
		if err != nil {
			gologger.Error().Msgf("could not setup ip6:tcp: %s\n", err)
		}

		listenHandler.UdpConn6, err = net.ListenIP("ip6:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", listenHandler.Port))})
		if err != nil {
			gologger.Error().Msgf("could not setup ip6:udp: %s\n", err)
		}

		go listenHandler.ICMPReadWorker4()
		go listenHandler.ICMPReadWorker6()
		go listenHandler.TcpReadWorker4()
		go listenHandler.TcpReadWorker6()
		go listenHandler.UdpReadWorker4()
		go listenHandler.UdpReadWorker6()

		ListenHandlers = append(ListenHandlers, &listenHandler)
	}

	handlers = &Handlers{}
	if err := SetupHandlers(); err != nil {
		panic(err)
	}
	go TransportReadWorker()
	go TransportWriteWorker()
	go ICMPWriteWorker()
}

// ICMPWriteWorker writes packet to the network layer
func ICMPWriteWorker() {
	for pkg := range icmpPacketSend {
		switch {
		case pkg.flag == IcmpEchoRequest:
			PingIcmpEchoRequestAsync(pkg.ip)
		case pkg.flag == IcmpTimestampRequest:
			PingIcmpTimestampRequestAsync(pkg.ip)
		case pkg.flag == IcmpAddressMaskRequest:
			PingIcmpAddressMaskRequestAsync(pkg.ip)
		case pkg.flag == Ndp:
			PingNdpRequestAsync(pkg.ip)
		}
	}
}

// EthernetWriteWorker writes packet to the network layer
func EthernetWriteWorker() {
	for pkg := range ethernetPacketSend {
		switch {
		case pkg.flag == Arp:
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
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	_, _, sourceIP, err := pkgRouter.Route(ip4.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
		return
	}
	ip4.SrcIP = sourceIP

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(listenHandler.Port),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == Syn {
		tcp.SYN = true
	} else if pkgFlag == Ack {
		tcp.ACK = true
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		err = send(ip, listenHandler.TcpConn4, &tcp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

func sendAsyncUDP4(listenHandler *ListenHandler, ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, sourceIP, err := pkgRouter.Route(ip4.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
		return
	}
	ip4.SrcIP = sourceIP

	udp := layers.UDP{
		SrcPort: layers.UDPPort(listenHandler.Port),
		DstPort: layers.UDPPort(p.Port),
	}

	err = udp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		err = send(ip, listenHandler.UdpConn4, &udp)
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

	_, _, sourceIP, err := pkgRouter.Route(ip6.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
		return
	}
	ip6.SrcIP = sourceIP

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(listenHandler.Port),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == Syn {
		tcp.SYN = true
	} else if pkgFlag == Ack {
		tcp.ACK = true
	}

	err = tcp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		err = send(ip, listenHandler.TcpConn6, &tcp)
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

	_, _, sourceIP, err := pkgRouter.Route(ip6.DstIP)
	if err != nil {
		gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
		return
	} else if sourceIP == nil {
		gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
		return
	}
	ip6.SrcIP = sourceIP

	udp := layers.UDP{
		SrcPort: layers.UDPPort(listenHandler.Port),
		DstPort: layers.UDPPort(p.Port),
	}

	err = udp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
	} else {
		err = send(ip, listenHandler.UdpConn6, &udp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
		}
	}
}

// ICMPReadWorker4 reads packets from the network layer
func (l *ListenHandler) ICMPReadWorker4() {
	data := make([]byte, 1500)
	for {
		n, addr, err := icmpConn4.ReadFrom(data)
		if err != nil {
			continue
		}

		rm, err := icmp.ParseMessage(ProtocolICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeTimestampReply:
			l.HostDiscoveryChan <- &PkgResult{ipv4: addr.String()}
		}
	}
}

// ICMPReadWorker6 reads packets from the network layer
func (l *ListenHandler) ICMPReadWorker6() {
	if icmpConn6 == nil {
		return
	}
	data := make([]byte, 1500)
	for {
		n, addr, err := icmpConn6.ReadFrom(data)
		if err != nil {
			continue
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
			l.HostDiscoveryChan <- &PkgResult{ipv6: ip}
		}
	}
}

var defaultSerializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// send sends the given layers as a single packet on the network.
func send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, defaultSerializeOptions, l...); err != nil {
		return err
	}

	var (
		retries int
		err     error
	)

send:
	if retries >= maxRetries {
		return err
	}
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
		goto send
	}
	return err
}

func (l *ListenHandler) TcpReadWorker4() {
	data := make([]byte, 4096)
	for {
		_, _, _ = l.TcpConn4.ReadFrom(data)
	}
}

func (l *ListenHandler) TcpReadWorker6() {
	if l.TcpConn6 == nil {
		return
	}
	data := make([]byte, 4096)
	for {
		_, _, _ = l.TcpConn6.ReadFrom(data)
	}
}

func (l *ListenHandler) UdpReadWorker4() {
	data := make([]byte, 4096)
	for {
		_, _, _ = l.UdpConn4.ReadFrom(data)
	}
}
func (l *ListenHandler) UdpReadWorker6() {
	if l.UdpConn6 == nil {
		return
	}
	data := make([]byte, 4096)
	for {
		_, _, _ = l.UdpConn6.ReadFrom(data)
	}
}

// SetupHandlerUnix on unix OS
func SetupHandlerUnix(interfaceName, bpfFilter string, protocols ...protocol.Protocol) error {
	for _, proto := range protocols {
		inactive, err := pcap.NewInactiveHandle(interfaceName)
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

		// Strict BPF filter
		// + Destination port equals to sender socket source port
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			return err
		}
		iface, err := net.InterfaceByName(interfaceName)
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
				if udpPortMatches {
					proto = protocol.UDP
				}
				listenHandler.HostDiscoveryChan <- &PkgResult{ipv4: srcIP4, ipv6: srcIP6, port: &port.Port{Port: int(tcp.SrcPort), Protocol: proto}}
			case tcpPortMatches && tcp.SYN && tcp.ACK:
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

			decoded := []gopacket.LayerType{}
			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
							srcIP4 := ToString(ip4.SrcIP)
							srcIP6 := ToString(ip6.SrcIP)
							transportReaderCallback(tcp, udp, srcIP4, srcIP6)
						}
					}
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

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

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

							for _, listenHandler := range ListenHandlers {
								listenHandler.HostDiscoveryChan <- &PkgResult{ipv4: ToString(srcIP4)}
							}
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
	var portFilters []string
	for _, listenHandler := range ListenHandlers {
		portFilters = append(portFilters, fmt.Sprintf("dst port %d", listenHandler.Port))
	}

	bpfFilter := fmt.Sprintf("(%s) and (tcp or udp)", strings.Join(portFilters, " or "))
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
	defer conn.Close()

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

	_, _, sourceIP, err := pkgRouter.Route(ip4.DstIP)
	if err != nil {
		return false, err
	}
	ip4.SrcIP = sourceIP

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

	err = send(dstIP, conn, &tcp)
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
