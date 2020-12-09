package scan

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// State determines the internal scan state
type State int

const (
	maxRetries     = 10
	sendDelayMsec  = 10
	chanSize       = 1000
	packetSendSize = 2500
	snaplen        = 65536
	readtimeout    = 1500
)

const (
	Init State = iota
	Scan
	Done
	Guard
)

// PkgFlag represent the TCP packet flag
type PkgFlag int

const (
	SYN PkgFlag = iota
	ACK
	ICMPECHOREQUEST
	ICMPTIMESTAMPREQUEST
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	SourceIP           net.IP
	tcpPacketlistener  net.PacketConn
	icmpPacketListener net.PacketConn
	retries            int
	rate               int
	listenPort         int
	timeout            time.Duration

	Ports    []int
	IPRanger *ipranger.IPRanger

	tcpPacketSend    chan *PkgSend
	icmpPacketSend   chan *PkgSend
	tcpChan          chan *PkgResult
	icmpChan         chan *PkgResult
	State            State
	ScanResults      *result.Result
	NetworkInterface *net.Interface
	cdn              *cdncheck.Client
	tcpsequencer     *TCPSequencer
	serializeOptions gopacket.SerializeOptions
	debug            bool
	handlers         []*pcap.Handle
	inactiveHandlers []*pcap.InactiveHandle
}

// PkgSend is a TCP package
type PkgSend struct {
	ip       string
	port     int
	flag     PkgFlag
	SourceIP string
}

// PkgResult contains the results of sending TCP packages
type PkgResult struct {
	ip   string
	port int
}

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(options *Options) (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

	iprang, err := ipranger.New()
	if err != nil {
		return nil, err
	}

	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout:      options.Timeout,
		retries:      options.Retries,
		rate:         options.Rate,
		debug:        options.Debug,
		tcpsequencer: NewTCPSequencer(),
		IPRanger:     iprang,
	}

	if options.Root {
		rawPort, err := freeport.GetFreePort()
		if err != nil {
			return nil, err
		}
		scanner.listenPort = rawPort

		tcpConn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", rawPort))})
		if err != nil {
			return nil, err
		}
		scanner.tcpPacketlistener = tcpConn

		scanner.tcpChan = make(chan *PkgResult, chanSize)
		scanner.tcpPacketSend = make(chan *PkgSend, packetSendSize)
	}

	scanner.ScanResults = result.NewResult()

	if options.ExcludeCdn {
		var err error
		scanner.cdn, err = cdncheck.NewWithCache()
		if err != nil {
			return nil, err
		}
	}

	return scanner, nil
}

// Close the scanner and terminate all workers
func (s *Scanner) Close() {
	s.CleanupHandlers()
	s.tcpPacketlistener.Close()
}

// StartWorkers of the scanner
func (s *Scanner) StartWorkers() {
	go s.TCPReadWorker()
	go s.TCPReadWorkerPCAP()
	go s.TCPWriteWorker()
	go s.TCPResultWorker()
}

// TCPWriteWorker that sends out TCP packets
func (s *Scanner) TCPWriteWorker() {
	for pkg := range s.tcpPacketSend {
		s.SendAsyncPkg(pkg.ip, pkg.port, pkg.flag)
	}
}

// TCPReadWorker reads and parse incoming TCP packets
func (s *Scanner) TCPReadWorker() {
	defer s.tcpPacketlistener.Close()
	data := make([]byte, 4096)
	for {
		if s.State == Done {
			break
		}
		// nolint:errcheck // just empty the buffer
		s.tcpPacketlistener.ReadFrom(data)
	}
}

// TCPReadWorkerPCAP reads and parse incoming TCP packets with pcap
func (s *Scanner) TCPReadWorkerPCAP() {
	defer s.CleanupHandlers()

	var wgread sync.WaitGroup

	for _, handler := range s.handlers {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				tcp layers.TCP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parserMac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
			// Interfaces without MAC (TUN/TAP)
			parserNoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parserMac, parserNoMac)

			decoded := []gopacket.LayerType{}

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					if err := parser.DecodeLayers(data, &decoded); err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeTCP {
							if !s.IPRanger.Contains(ip4.SrcIP.String()) {
								gologger.Debugf("Discarding TCP packet from non target ip %s\n", ip4.SrcIP.String())
								continue
							}

							// We consider only incoming packets
							if tcp.DstPort != layers.TCPPort(s.listenPort) {
								continue
							} else if tcp.SYN && tcp.ACK {
								s.tcpChan <- &PkgResult{ip: ip4.SrcIP.String(), port: int(tcp.SrcPort)}
							}
						}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// EnqueueICMP outgoing ICMP packets
func (s *Scanner) EnqueueICMP(ip string, pkgtype PkgFlag) {
	s.icmpPacketSend <- &PkgSend{
		ip:   ip,
		flag: pkgtype,
	}
}

// EnqueueTCP outgoing TCP packets
func (s *Scanner) EnqueueTCP(ip string, port int, pkgtype PkgFlag) {
	s.tcpPacketSend <- &PkgSend{
		ip:   ip,
		port: port,
		flag: pkgtype,
	}
}

// ICMPWriteWorker writes packet to the network layer
func (s *Scanner) ICMPWriteWorker() {
	for pkg := range s.icmpPacketSend {
		if pkg.flag == ICMPECHOREQUEST {
			s.PingIcmpEchoRequestAsync(pkg.ip)
		} else if pkg.flag == ICMPTIMESTAMPREQUEST {
			s.PingIcmpTimestampRequestAsync(pkg.ip)
		}
	}
}

// ICMPReadWorker reads packets from the network layer
func (s *Scanner) ICMPReadWorker() {
	defer s.icmpPacketListener.Close()
	data := make([]byte, 1500)
	for {
		if s.State == Done {
			break
		}
		n, addr, err := s.icmpPacketListener.ReadFrom(data)
		if err != nil {
			continue
		}

		if s.State == Guard {
			continue
		}

		rm, err := icmp.ParseMessage(ProtocolICMP, data[:n])
		if err != nil {
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeTimestamp:
			s.icmpChan <- &PkgResult{ip: addr.String()}
		}
	}
}

// TCPResultWorker handles probes and scan results
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		if s.State == Scan {
			gologger.Debugf("Received TCP scan response from %s:%d\n", ip.ip, ip.port)
			s.ScanResults.AddPort(ip.ip, ip.port)
		}
	}
}

// GetSrcParameters gets the network parameters from the destination ip
func GetSrcParameters(destIP string) (srcIP net.IP, networkInterface *net.Interface, err error) {
	srcIP, err = GetSourceIP(net.ParseIP(destIP))
	if err != nil {
		return
	}

	networkInterface, err = GetInterfaceFromIP(srcIP)
	if err != nil {
		return
	}

	return
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
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

// ScanSyn a target ip
func (s *Scanner) ScanSyn(ip string) {
	for _, port := range s.Ports {
		s.EnqueueTCP(ip, port, SYN)
	}
}

// GetSourceIP gets the local ip based on our destination ip
func GetSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	con, dialUpErr := net.DialUDP("udp", nil, serverAddr)
	if dialUpErr != nil {
		return nil, dialUpErr
	}

	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return nil, nil
}

// GetInterfaceFromIP gets the name of the network interface from local ip address
func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			// Check if the IP for the current interface is our
			// source IP. If yes, return the interface
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}

// ConnectPort a single host and port
func ConnectPort(host string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, err
}

// ACKPort sends an ACK packet to a port
func (s *Scanner) ACKPort(dstIP string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return false, err
	}

	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		SrcIP:    s.SourceIP,
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: layers.TCPPort(port),
		ACK:     true,
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return false, err
	}

	err = s.send(dstIP, conn, &tcp)
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
			if s.debug {
				gologger.Debugf("Discarding TCP packet from non target ip %s for %s\n", dstIP, addr.String())
			}
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// We consider only incoming packets
			if tcp.DstPort != layers.TCPPort(rawPort) {
				if s.debug {
					gologger.Debugf("Discarding TCP packet from %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, dstIP, rawPort)
				}
				continue
			} else if tcp.RST {
				if s.debug {
					gologger.Debugf("Accepting RST packet from %s:%d\n", addr.String(), tcp.DstPort)
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// SendAsyncPkg sends a single packet to a port
func (s *Scanner) SendAsyncPkg(ip string, port int, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		SrcIP:    s.SourceIP,
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == SYN {
		tcp.SYN = true
	} else if pkgFlag == ACK {
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		if s.debug {
			gologger.Debugf("Can not set network layer for %s:%d port: %s\n", ip, port, err)
		}
	} else {
		err = s.send(ip, s.tcpPacketlistener, &tcp)
		if err != nil {
			if s.debug {
				gologger.Debugf("Can not send packet to %s:%d port: %s\n", ip, port, err)
			}
		}
	}
}

// TuneSource automatically with ip and interface
func (s *Scanner) TuneSource(ip string) error {
	var err error
	s.SourceIP, s.NetworkInterface, err = GetSrcParameters(ip)
	if err != nil {
		return err
	}

	return nil
}

// SetupHandlers to listen on all interfaces
func (s *Scanner) SetupHandlers() error {
	if s.NetworkInterface != nil {
		return s.SetupHandler(s.NetworkInterface.Name)
	}

	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		if itf.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		s.SetupHandler(itf.Name)
	}

	return nil
}

// SetupHandler to listen on the specified interface
func (s *Scanner) SetupHandler(interfaceName string) error {
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
		s.CleanupHandlers()
		return err
	}
	err = inactive.SetImmediateMode(true)
	if err != nil {
		return err
	}

	s.inactiveHandlers = append(s.inactiveHandlers, inactive)

	handle, err := inactive.Activate()
	if err != nil {
		s.CleanupHandlers()
		return err
	}

	s.handlers = append(s.handlers, handle)

	// Strict BPF filter
	// + Packets coming from target ip
	// + Destination port equals to sender socket source port
	err = handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d and tcp[13]=18", s.listenPort))
	if err != nil {
		s.CleanupHandlers()
		return err
	}

	return nil
}

// CleanupHandlers for all interfaces
func (s *Scanner) CleanupHandlers() {
	for _, handler := range s.handlers {
		handler.Close()
	}
	for _, inactiveHandler := range s.inactiveHandlers {
		inactiveHandler.CleanUp()
	}
}
