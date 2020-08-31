package scan

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/phayes/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/pkg/KV"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ScanState int

const (
	Init ScanState = iota
	Probe
	Scan
	Done
)

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
	Targets        map[string]struct{}
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
	State              ScanState
	ScanResults        *KV.KVD

	NetworkInterface *net.Interface
	SourceIP         net.IP
	tcpsequencer     *TCPSequencer
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

	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}
	scanner.listenPort = rawPort

	tcpConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
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
	scanner.icmpPacketSend = make(chan *PkgSend)
	scanner.tcpChan = make(chan *PkgResult, 1000)
	scanner.tcpPacketSend = make(chan *PkgSend)

	scanner.ProbeResults = KV.NewKV()
	scanner.ScanResults = KV.NewKVResults()

	return scanner, nil
}

func (s *Scanner) Close() {
	s.tcpPacketlistener.Close()
	s.icmpPacketListener.Close()
}

func (s *Scanner) StartWorkers() {
	go s.TCPReadWorker()
	go s.TCPWriteWorker()
	go s.ICMPReadWorker()
	go s.ICMPWriteWorker()
	go s.ICMPResultWorker()
	go s.TCPResultWorker()
}

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

		_, ok := s.Targets[addr.String()]
		if !ok {
			gologger.Debugf("Discarding TCP packet from %s not matching %s ip\n", addr.String())
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
				gologger.Debugf("Discarding TCP packet to %s:%d not matching port %d port\n", addr.String(), tcp.DstPort, s.listenPort)
			} else if tcp.SYN && tcp.ACK {
				if s.debug {
					gologger.Debugf("Accepting SYN+ACK packet from %s:%d\n", addr.String(), tcp.DstPort)
				}
				s.tcpChan <- &PkgResult{ip: addr.String(), port: int(tcp.SrcPort)}
			}
		}
	}
}

func (s *Scanner) EnqueueICMP(ip string, pkgtype PkgFlag) {
	s.icmpPacketSend <- &PkgSend{
		ip:   ip,
		flag: pkgtype,
	}
}

func (s *Scanner) EnqueueTCP(ip string, port int, pkgtype PkgFlag) {
	s.tcpPacketSend <- &PkgSend{
		ip:   ip,
		port: port,
		flag: pkgtype,
	}
}

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

func (s *Scanner) ICMPResultWorker() {
	for ip := range s.icmpChan {
		switch s.State {
		case Probe:
			log.Printf("PROBE %+v\n", ip)
			s.ProbeResults.Set(ip.ip)
		case Scan:
			// Discard
		}
	}
}

func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		switch s.State {
		case Probe:
			log.Printf("PROBE %+v\n", ip)
			s.ProbeResults.Set(ip.ip)
		case Scan:
			log.Printf("RESULT %+v\n", ip)
			s.ScanResults.AddPort(ip.ip, ip.port)
		}
	}
}

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

func (s *Scanner) ScanSyn(ip string) {
	for port := range s.Ports {
		s.SynPortAsync(ip, port)
	}
}

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
		Seq:     uint32(s.tcpsequencer.One()),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	// maybe should be moved after listening - WIP
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
				gologger.Debugf("Discarding TCP packet from %s not matching %s ip\n", addr.String(), dstIP)
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
					gologger.Debugf("Discarding TCP packet to %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, dstIP, rawPort)
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

// ConnectPort a single host and port
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
		Seq:     uint32(s.tcpsequencer.One()),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	s.send(ip, s.tcpPacketlistener, &tcp)
}

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
		Seq:     uint32(s.tcpsequencer.One()),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	s.send(ip, s.tcpPacketlistener, &tcp)
}

func (s *Scanner) TuneSource(ip string) error {
	var err error
	s.SourceIP, s.NetworkInterface, err = GetSrcParameters(ip)
	if err != nil {
		return err
	}

	return nil
}
