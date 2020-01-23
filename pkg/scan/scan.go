package scan

import (
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/phayes/freeport"
)

// Scanner is a scanner that scans for ports using SYN packets.
type Scanner struct {
	timeout          time.Duration
	serializeOptions gopacket.SerializeOptions
	retries          int
	rate             int

	host  net.IP
	srcIP net.IP

	Latency time.Duration
}

// Result is a port or an error returned from the scanner
type Result struct {
	Port  int
	Type  ResultType
	Error error
}

// ResultType is the type of result returned
type ResultType int

// Types of results retured
const (
	ResultPort ResultType = iota
	ResultError
)

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(host net.IP, timeout time.Duration, retries, rate int) (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout: timeout,
		retries: retries,
		host:    host,
		rate:    rate,

		Latency: -1,
	}

	var err error
	scanner.srcIP, err = localIPPort(host)
	if err != nil {
		return nil, err
	}

	return scanner, nil
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(conn net.PacketConn, dstip net.IP, l ...gopacket.SerializableLayer) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return 0, err
	}
	return conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip})
}

// Scan scans a single host and returns the results
func (s *Scanner) Scan(wordlist map[int]struct{}) (map[int]struct{}, error) {
	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	readTimeout := time.Duration(1500) * time.Millisecond

	openChan := make(chan int)
	results := make(map[int]struct{})
	resultsWg := &sync.WaitGroup{}
	resultsWg.Add(1)

	startTime := time.Now()

	go func() {
		for open := range openChan {
			// Set latency if the latency is less than 0 or
			// more than the default latency.
			latency := time.Since(startTime)
			if s.Latency < 0 {
				s.Latency = latency
			}
			results[open] = struct{}{}
		}
		resultsWg.Done()
	}()

	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		SrcIP:    s.srcIP,
		DstIP:    s.host,
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}
	randSeq := 1000000000 + rand.Intn(8999999999)

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort),
		DstPort: 0,
		SYN:     true,
		Window:  1024,
		Seq:     uint32(randSeq),
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	tasksWg := &sync.WaitGroup{}
	tasksWg.Add(1)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err == io.EOF {
				break
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				// read timeout
				break
			} else if err != nil {
				continue
			} else if addr.String() != s.host.String() {
				// mismatching ip
				continue
			}

			conn.SetReadDeadline(time.Now().Add(readTimeout))

			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.SYN && tcp.ACK {
					openChan <- int(tcp.SrcPort)
				}
			}
		}
		tasksWg.Done()
	}()

	limiter := time.Tick(time.Second / time.Duration(s.rate))

	ports := make(chan int)
	go func() {
		for port := range ports {
			// Increment sequence number from initial seed.
			// Some firewalls drop requests if Sequence values
			// are not incremental.
			randSeq += 1 + rand.Intn(5)
			tcp.Seq = uint32(randSeq)
			tcp.DstPort = layers.TCPPort(port)
			for i := 0; i < s.retries; i++ {
				<-limiter
				n, err := s.send(conn, ip4.DstIP, &tcp)
				if n > 0 && err == nil {
					break
				}
			}
		}
	}()

	for port := range wordlist {
		ports <- port
	}
	close(ports)

	// Just like masscan, wait for 10 seconds for further packets
	if s.timeout > 0 {
		timer := time.AfterFunc(10*time.Second, func() { conn.Close() })
		defer timer.Stop()
	} else {
		conn.Close()
	}

	tasksWg.Wait()
	close(openChan)
	resultsWg.Wait()

	return results, nil
}

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, error) {
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
