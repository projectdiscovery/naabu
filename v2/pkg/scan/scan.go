package scan

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/KV"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// State determines the internal scan state
type State int

const (
	Init State = iota
	Probe
	Scan
	Done
	Guard
)

// PkgFlag represent the TCP packet flag
type PkgFlag int

const (
	SYN PkgFlag = iota
	ACK
	ICMP_ECHO_REQUEST
	ICMP_TIMESTAMP_REQUEST
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	Ports          map[int]struct{}
	ExcludedIps    map[string]struct{}
	wg             sync.WaitGroup
	Targets        map[string]map[string]struct{}
	ProbeResults   *KV.KV
	SynProbesPorts map[int]struct{}
	AckProbesPorts map[int]struct{}

	timeout            time.Duration
	serializeOptions   gopacket.SerializeOptions
	retries            int
	rate               int
	debug              bool
	tcpPacketRecv      chan int
	tcpPacketSend      chan *PkgSend
	tcpPacketlistener  net.PacketConn
	icmpPacketRecv     chan int
	icmpPacketSend     chan *PkgSend
	icmpPacketListener net.PacketConn
	listenPort         int
	tcpChan            chan *PkgResult
	icmpChan           chan *PkgResult
	State              State
	ScanResults        *KV.KVD

	NetworkInterface *net.Interface
	SourceIP         net.IP
	tcpsequencer     *TCPSequencer
	cdn              *cdncheck.Client
}

type PkgSend struct {
	ip       string
	port     int
	flag     PkgFlag
	sourceIp string
}

type PkgResult struct {
	ip   string
	port int
}

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(options *Options) (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

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

		icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return nil, err
		}
		scanner.icmpPacketListener = icmpConn

		scanner.icmpChan = make(chan *PkgResult, 1000)
		scanner.icmpPacketSend = make(chan *PkgSend, 2500)
		scanner.tcpChan = make(chan *PkgResult, 1000)
		scanner.tcpPacketSend = make(chan *PkgSend, 2500)
	}

	scanner.ProbeResults = KV.NewKV()
	scanner.ScanResults = KV.NewKVResults()

	var err error
	scanner.cdn, err = cdncheck.New()
	if err != nil {
		return nil, err
	}

	return scanner, nil
}

// Close the scanner and terminate all workers
func (s *Scanner) Close() {
	s.tcpPacketlistener.Close()
	s.icmpPacketListener.Close()
}

// StartWorkers of the scanner
func (s *Scanner) StartWorkers() {
	go s.TCPReadWorker()
	go s.TCPWriteWorker()
	go s.ICMPReadWorker()
	go s.ICMPWriteWorker()
	go s.ICMPResultWorker()
	go s.TCPResultWorker()
}

// TCPWriteWorker that sends out TCP packets
func (s *Scanner) TCPWriteWorker() {
	for pkg := range s.tcpPacketSend {
		switch pkg.flag {
		case SYN:
			s.SynPortAsync(pkg.ip, pkg.port)
		case ACK:
			s.ACKPortAsync(pkg.ip, pkg.port)
		}
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
		n, addr, err := s.tcpPacketlistener.ReadFrom(data)
		if err != nil {
			break
		}

		if s.State == Guard {
			continue
		}

		_, ok := s.Targets[addr.String()]
		if !ok {
			gologger.Debugf("Discarding TCP packet from non target ip %s\n", addr.String())
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// We consider only incoming packets
			if tcp.DstPort != layers.TCPPort(s.listenPort) {
				gologger.Debugf("Discarding TCP packet from %s:%d not matching port %d port\n", addr.String(), tcp.DstPort, s.listenPort)
			} else if tcp.SYN && tcp.ACK {
				if s.debug {
					gologger.Debugf("Accepting SYN+ACK packet from %s:%d\n", addr.String(), tcp.DstPort)
				}
				s.tcpChan <- &PkgResult{ip: addr.String(), port: int(tcp.SrcPort)}
			}
		}
	}
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
		switch pkg.flag {
		case ICMP_ECHO_REQUEST:
			s.PingIcmpEchoRequestAsync(pkg.ip)
		case ICMP_TIMESTAMP_REQUEST:
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

// ICMPResultWorker handles ICMP responses (used only during probes)
func (s *Scanner) ICMPResultWorker() {
	for ip := range s.icmpChan {
		switch s.State {
		case Guard:
			// ignore as working internally on data structures
		case Probe:
			gologger.Debugf("Received ICMP response from %s\n", ip.ip)
			s.ProbeResults.Set(ip.ip)
		case Scan:
			// Discard
		}
	}
}

// TCPResultWorker handles probes and scan results
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		switch s.State {
		case Guard:
			// ignore as working internally on data structures
		case Probe:
			gologger.Debugf("Received TCP probe response from %s:%d\n", ip.ip, ip.port)
			s.ProbeResults.Set(ip.ip)
		case Scan:
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
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return 0, err
	}

	var (
		retries, n int
		err        error
	)

send:
	if retries >= 10 {
		return n, err
	}
	n, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(10) * time.Millisecond)
		goto send
	}
	return n, err
}

// ScanSyn a target ip
func (s *Scanner) ScanSyn(ip string) {
	for port := range s.Ports {
		s.EnqueueTCP(ip, port, SYN)
	}
}

// GetSourceIP gets the local ip based on our destination ip
func GetSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		defer con.Close()
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, nil
		}
	}
	return nil, err
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
	defer conn.Close()
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
	tcp.SetNetworkLayerForChecksum(&ip4)

	s.send(dstIP, conn, &tcp)

	data := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(data)
		if err != nil {
			break
		}

		// not matching ip
		if addr.String() != dstIP {
			if s.debug {
				gologger.Debugf("Discarding TCP packet from non target ip %s\n", addr.String(), dstIP)
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

// SynPortAsync sends a single SYN packet to a port
func (s *Scanner) SynPortAsync(ip string, port int) {
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
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	s.send(ip, s.tcpPacketlistener, &tcp)
}

// ACKPortAsync sends a single ACK packet to a port
func (s *Scanner) ACKPortAsync(ip string, port int) {
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
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		ACK:     true,
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	s.send(ip, s.tcpPacketlistener, &tcp)
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
