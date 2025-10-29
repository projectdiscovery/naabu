package scan

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/utils/limits"
	"github.com/projectdiscovery/networkpolicy"
	envutil "github.com/projectdiscovery/utils/env"
	"golang.org/x/net/proxy"
)

// State determines the internal scan state
type State int

const (
	maxRetries     = 10
	sendDelayMsec  = 10
	chanSize       = 1000  //nolint
	packetSendSize = 2500  //nolint
	snaplen        = 65536 //nolint
	readtimeout    = 1500  //nolint
)

const (
	Init State = iota
	HostDiscovery
	Scan
	Done
	Guard
)

type Phase struct {
	sync.RWMutex
	State
}

func (phase *Phase) Is(state State) bool {
	phase.RLock()
	defer phase.RUnlock()

	return phase.State == state
}

func (phase *Phase) Set(state State) {
	phase.Lock()
	defer phase.Unlock()

	phase.State = state
}

// PkgFlag represent the TCP packet flag
type PkgFlag int

const (
	Syn PkgFlag = iota
	Ack
	IcmpEchoRequest
	IcmpTimestampRequest
	IcmpAddressMaskRequest
	Arp
	Ndp
)

type Scanner struct {
	retries       int
	rate          int
	portThreshold int
	timeout       time.Duration
	proxyDialer   proxy.Dialer

	Ports    []*port.Port
	IPRanger *ipranger.IPRanger

	HostDiscoveryResults *result.Result
	ScanResults          *result.Result
	NetworkInterface     *net.Interface
	cdn                  *cdncheck.Client
	tcpsequencer         *TCPSequencer
	stream               bool
	ListenHandler        *ListenHandler
	OnReceive            result.ResultFn
}

// PkgSend is a TCP package
type PkgSend struct {
	ListenHandler *ListenHandler
	ip            string
	port          *port.Port
	flag          PkgFlag
	SourceIP      string
}

// PkgResult contains the results of sending TCP packages
type PkgResult struct {
	ipv4 string
	ipv6 string
	port *port.Port
}

var (
	pingIcmpEchoRequestCallback      func(ip string, timeout time.Duration) bool              //nolint
	pingIcmpTimestampRequestCallback func(ip string, timeout time.Duration) bool              //nolint
	EnableTLSDetection               = envutil.GetEnvOrDefault("ENABLE_TLS_DETECTION", false) // Enable TLS detection for connect scans
)

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(options *Options) (*Scanner, error) {
	iprang, err := ipranger.New()
	if err != nil {
		return nil, err
	}

	var nPolicyOptions *networkpolicy.Options
	if options.NetworkPolicyOptions != nil {
		nPolicyOptions = options.NetworkPolicyOptions
	} else {
		nPolicyOptions = &networkpolicy.Options{}
	}

	nPolicyOptions.DenyList = append(nPolicyOptions.DenyList, options.ExcludedIps...)
	nPolicy, err := networkpolicy.New(*nPolicyOptions)
	if err != nil {
		return nil, err
	}
	iprang.Np = nPolicy

	scanner := &Scanner{
		timeout:       options.Timeout,
		retries:       options.Retries,
		rate:          options.Rate,
		portThreshold: options.PortThreshold,
		tcpsequencer:  NewTCPSequencer(),
		IPRanger:      iprang,
		OnReceive:     options.OnReceive,
	}

	scanner.HostDiscoveryResults = result.NewResult()
	scanner.ScanResults = result.NewResult()
	if options.ExcludeCdn || options.OutputCdn {
		scanner.cdn = cdncheck.New()
	}

	var auth *proxy.Auth = nil

	if options.ProxyAuth != "" && strings.Contains(options.ProxyAuth, ":") {
		credentials := strings.SplitN(options.ProxyAuth, ":", 2)
		var user, password string
		user = credentials[0]
		if len(credentials) == 2 {
			password = credentials[1]
		}
		auth = &proxy.Auth{User: user, Password: password}
	}

	if options.Proxy != "" {
		proxyDialer, err := proxy.SOCKS5("tcp", options.Proxy, auth, &net.Dialer{Timeout: limits.TimeoutWithProxy(options.Timeout)})
		if err != nil {
			return nil, err
		}
		scanner.proxyDialer = proxyDialer
	}

	scanner.stream = options.Stream
acquire:
	if handler, err := Acquire(options); err != nil {
		// automatically fallback to connect scan
		if options.ScanType == "s" {
			gologger.Info().Msgf("syn scan is not possible, falling back to connect scan")
			options.ScanType = "c"
			goto acquire
		}
		return scanner, err
	} else {
		scanner.ListenHandler = handler
	}

	return scanner, err
}

// Close the scanner and terminate all workers
func (s *Scanner) Close() error {
	s.ListenHandler.Busy = false
	s.ListenHandler = nil

	return nil
}

// StartWorkers of the scanner
func (s *Scanner) StartWorkers(ctx context.Context) {
	go s.ICMPResultWorker(ctx)
	go s.TCPResultWorker(ctx)
	go s.UDPResultWorker(ctx)
}

// EnqueueICMP outgoing ICMP packets
func (s *Scanner) EnqueueICMP(ip string, pkgtype PkgFlag) {
	icmpPacketSend <- &PkgSend{
		ListenHandler: s.ListenHandler,
		ip:            ip,
		flag:          pkgtype,
	}
}

// EnqueueEthernet outgoing Ethernet packets
func (s *Scanner) EnqueueEthernet(ip string, pkgtype PkgFlag) {
	ethernetPacketSend <- &PkgSend{
		ListenHandler: s.ListenHandler,
		ip:            ip,
		flag:          pkgtype,
	}
}

// EnqueueTCP outgoing TCP packets
func (s *Scanner) EnqueueTCP(ip string, pkgtype PkgFlag, ports ...*port.Port) {
	for _, port := range ports {
		transportPacketSend <- &PkgSend{
			ListenHandler: s.ListenHandler,
			ip:            ip,
			port:          port,
			flag:          pkgtype,
		}
	}
}

// EnqueueTCP outgoing TCP packets
func (s *Scanner) EnqueueUDP(ip string, ports ...*port.Port) {
	for _, port := range ports {
		transportPacketSend <- &PkgSend{
			ListenHandler: s.ListenHandler,
			ip:            ip,
			port:          port,
		}
	}
}

// ICMPResultWorker handles ICMP responses (used only during probes)
func (s *Scanner) ICMPResultWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-s.ListenHandler.HostDiscoveryChan:
			if s.ListenHandler.Phase.Is(HostDiscovery) {
				gologger.Debug().Msgf("Received ICMP response from %s\n", ip.ipv4)
				if ip.ipv4 != "" {
					s.HostDiscoveryResults.AddIp(ip.ipv4)
				}
				if ip.ipv6 != "" {
					s.HostDiscoveryResults.AddIp(ip.ipv6)
				}
			}
		}
	}
}

// TCPResultWorker handles probes and scan results
func (s *Scanner) TCPResultWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-s.ListenHandler.TcpChan:
			srcIP4WithPort := net.JoinHostPort(ip.ipv4, ip.port.String())
			srcIP6WithPort := net.JoinHostPort(ip.ipv6, ip.port.String())
			isIPInRange := s.IPRanger.ContainsAny(srcIP4WithPort, srcIP6WithPort, ip.ipv4, ip.ipv6)
			if !isIPInRange {
				gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", ip.ipv4, ip.ipv6)
				continue
			}

			if s.OnReceive != nil {
				singlePort := []*port.Port{ip.port}
				if ip.ipv4 != "" {
					s.OnReceive(&result.HostResult{IP: ip.ipv4, Ports: singlePort})
				}
				if ip.ipv6 != "" {
					s.OnReceive(&result.HostResult{IP: ip.ipv6, Ports: singlePort})
				}
			}
			if s.ListenHandler.Phase.Is(HostDiscovery) {
				gologger.Debug().Msgf("Received Transport (TCP|UDP) probe response from ipv4:%s ipv6:%s port:%d\n", ip.ipv4, ip.ipv6, ip.port.Port)
				if ip.ipv4 != "" {
					s.HostDiscoveryResults.AddIp(ip.ipv4)
				}
				if ip.ipv6 != "" {
					s.HostDiscoveryResults.AddIp(ip.ipv6)
				}
			} else if s.ListenHandler.Phase.Is(Scan) || s.stream {
				gologger.Debug().Msgf("Received Transport (TCP) scan response from ipv4:%s ipv6:%s port:%d\n", ip.ipv4, ip.ipv6, ip.port.Port)
				if ip.ipv4 != "" {
					s.ScanResults.AddPort(ip.ipv4, ip.port)
				}
				if ip.ipv6 != "" {
					s.ScanResults.AddPort(ip.ipv6, ip.port)
				}
			}
		}
	}
}

// UDPResultWorker handles probes and scan results
func (s *Scanner) UDPResultWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-s.ListenHandler.UdpChan:
			srcIP4WithPort := net.JoinHostPort(ip.ipv4, ip.port.String())
			srcIP6WithPort := net.JoinHostPort(ip.ipv6, ip.port.String())
			isIPInRange := s.IPRanger.ContainsAny(srcIP4WithPort, srcIP6WithPort, ip.ipv4, ip.ipv6)
			if !isIPInRange {
				gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", ip.ipv4, ip.ipv6)
				continue
			}

			if s.ListenHandler.Phase.Is(HostDiscovery) {
				gologger.Debug().Msgf("Received UDP probe response from ipv4:%s ipv6:%s port:%d\n", ip.ipv4, ip.ipv6, ip.port.Port)
				if ip.ipv4 != "" {
					s.HostDiscoveryResults.AddIp(ip.ipv4)
				}
				if ip.ipv6 != "" {
					s.HostDiscoveryResults.AddIp(ip.ipv6)
				}
			} else if s.ListenHandler.Phase.Is(Scan) || s.stream {
				gologger.Debug().Msgf("Received Transport (UDP) scan response from from ipv4:%s ipv6:%s port:%d\n", ip.ipv4, ip.ipv6, ip.port.Port)
				if ip.ipv4 != "" {
					s.ScanResults.AddPort(ip.ipv4, ip.port)
				}
				if ip.ipv6 != "" {
					s.ScanResults.AddPort(ip.ipv6, ip.port)
				}
			}
		}
	}
}

// ScanSyn a target ip
func (s *Scanner) ScanSyn(ip string) {
	for _, port := range s.Ports {
		s.EnqueueTCP(ip, Syn, port)
	}
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

// detectTLS sends a ClientHello and checks for TLS response
func detectTLS(conn net.Conn, host string, timeout time.Duration) bool {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		now := time.Now().Unix()
		for i := 0; i < 32; i++ {
			random[i] = byte(now >> uint(i*8))
		}
	}

	hostname := ""
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			hostname = host
		}
	}

	var sniExtension []byte
	var extensions []byte
	var extensionsLength int

	if hostname != "" {
		hostnameBytes := []byte(hostname)
		sniListLength := 1 + 2 + len(hostnameBytes)
		sniLength := 2 + sniListLength
		sniExtension = make([]byte, 4+sniLength)
		sniExtension[0] = 0x00 // extension type: server_name
		sniExtension[1] = 0x00
		sniExtension[2] = byte(sniLength >> 8) // extension length
		sniExtension[3] = byte(sniLength)
		sniExtension[4] = byte(sniListLength >> 8) // server_name_list length
		sniExtension[5] = byte(sniListLength)
		sniExtension[6] = 0x00                          // name_type: host_name
		sniExtension[7] = byte(len(hostnameBytes) >> 8) // hostname length
		sniExtension[8] = byte(len(hostnameBytes))
		copy(sniExtension[9:], hostnameBytes)

		extensions = sniExtension
		extensionsLength = len(extensions)
	}

	clientHelloBodyLength := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensionsLength
	handshakeLength := 4 + clientHelloBodyLength
	recordLength := handshakeLength
	clientHello := make([]byte, 5+handshakeLength)
	offset := 0

	// TLS record header
	clientHello[offset] = 0x16                      // content type: Handshake
	clientHello[offset+1] = 0x03                    // version: TLS 1.0 (major)
	clientHello[offset+2] = 0x01                    // version: TLS 1.0 (minor)
	clientHello[offset+3] = byte(recordLength >> 8) // length (high)
	clientHello[offset+4] = byte(recordLength)      // length (low)
	offset += 5

	// Handshake header
	clientHello[offset] = 0x01                                // handshake type: ClientHello
	clientHello[offset+1] = byte(clientHelloBodyLength >> 16) // length (high)
	clientHello[offset+2] = byte(clientHelloBodyLength >> 8)  // length (mid)
	clientHello[offset+3] = byte(clientHelloBodyLength)       // length (low)
	offset += 4

	// ClientHello message
	clientHello[offset] = 0x03   // version: TLS 1.2 (major)
	clientHello[offset+1] = 0x03 // version: TLS 1.2 (minor)
	offset += 2
	copy(clientHello[offset:], random) // random (32 bytes)
	offset += 32
	clientHello[offset] = 0x00 // session_id length
	offset++
	clientHello[offset] = 0x00   // cipher_suites length (high)
	clientHello[offset+1] = 0x02 // cipher_suites length (low)
	offset += 2
	clientHello[offset] = 0x00   // cipher_suite: TLS_RSA_WITH_AES_128_CBC_SHA (high)
	clientHello[offset+1] = 0x2f // cipher_suite (low)
	offset += 2
	clientHello[offset] = 0x01 // compression_methods length
	offset++
	clientHello[offset] = 0x00 // compression_method: null
	offset++
	clientHello[offset] = byte(extensionsLength >> 8) // extensions length (high)
	clientHello[offset+1] = byte(extensionsLength)    // extensions length (low)
	offset += 2
	if extensionsLength > 0 {
		copy(clientHello[offset:], extensions)
		offset += extensionsLength
	}

	actualRecordLength := offset - 5
	clientHello[3] = byte(actualRecordLength >> 8)
	clientHello[4] = byte(actualRecordLength)

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	if _, err := conn.Write(clientHello[:offset]); err != nil {
		return false
	}
	readTimeout := 2 * time.Second
	if timeout < readTimeout {
		readTimeout = timeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return false
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil && !os.IsTimeout(err) {
		return false
	}

	if n < 5 {
		return false
	}

	// check content type (0x15=Alert, 0x16=Handshake)
	contentType := buffer[0]
	if contentType != 0x15 && contentType != 0x16 {
		return false
	}

	// check TLS version (major must be 0x03)
	if buffer[1] != 0x03 {
		return false
	}

	// if handshake, check for ServerHello (0x02)
	if contentType == 0x16 && n >= 6 {
		if buffer[5] == 0x02 {
			return true
		}
	}

	return true
}

// ConnectPort a single host and port
func (s *Scanner) ConnectPort(host, payload string, p *port.Port, timeout time.Duration) (bool, error) {
	hostport := net.JoinHostPort(host, fmt.Sprint(p.Port))
	var (
		err  error
		conn net.Conn
	)
	if s.proxyDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), limits.TimeoutWithProxy(timeout))
		defer cancel()
		proxyDialer, ok := s.proxyDialer.(proxy.ContextDialer)
		if !ok {
			return false, errors.New("invalid proxy dialer")
		}
		conn, err = proxyDialer.DialContext(ctx, p.Protocol.String(), hostport)
		if err != nil {
			return false, err
		}
	} else {
		netDialer := net.Dialer{
			Timeout: timeout,
		}
		if s.ListenHandler.SourceIp4 != nil {
			netDialer.LocalAddr = &net.TCPAddr{IP: s.ListenHandler.SourceIp4}
		} else if s.ListenHandler.SourceIP6 != nil {
			netDialer.LocalAddr = &net.TCPAddr{IP: s.ListenHandler.SourceIP6}
		}
		conn, err = netDialer.Dial(p.Protocol.String(), hostport)
	}
	if err != nil {
		return false, err
	}
	defer func() {
		_ = conn.Close()
	}()

	// udp needs data probe
	switch p.Protocol {
	case protocol.UDP:
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			return false, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		n, err := io.Copy(io.Discard, conn)
		// ignore timeout errors
		if err != nil && !os.IsTimeout(err) {
			return false, err
		}
		return n > 0, nil
	case protocol.TCP:
		// Perform TLS detection for TCP connections if enabled
		if EnableTLSDetection {
			//nolint
			p.TLS = detectTLS(conn, host, timeout)
		}
	}

	return true, err
}
