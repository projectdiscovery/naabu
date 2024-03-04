package scan

import (
	"context"
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
	"github.com/projectdiscovery/networkpolicy"
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
	SourceIP4     net.IP
	SourceIP6     net.IP
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
	pingIcmpEchoRequestCallback      func(ip string, timeout time.Duration) bool //nolint
	pingIcmpTimestampRequestCallback func(ip string, timeout time.Duration) bool //nolint
)

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(options *Options) (*Scanner, error) {
	iprang, err := ipranger.New()
	if err != nil {
		return nil, err
	}

	var nPolicyOptions networkpolicy.Options
	nPolicyOptions.DenyList = append(nPolicyOptions.DenyList, options.ExcludedIps...)
	nPolicy, err := networkpolicy.New(nPolicyOptions)
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
		proxyDialer, err := proxy.SOCKS5("tcp", options.Proxy, auth, &net.Dialer{Timeout: options.Timeout})
		if err != nil {
			return nil, err
		}
		scanner.proxyDialer = proxyDialer
	}

	scanner.stream = options.Stream

	if handler, err := Acquire(); err != nil {
		return scanner, err
	} else {
		scanner.ListenHandler = handler
	}

	return scanner, err
}

// Close the scanner and terminate all workers
func (s *Scanner) Close() {
	s.ListenHandler.Busy = false
	s.ListenHandler = nil
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

// ConnectPort a single host and port
func (s *Scanner) ConnectPort(host string, p *port.Port, timeout time.Duration) (bool, error) {
	hostport := net.JoinHostPort(host, fmt.Sprint(p.Port))
	var (
		err  error
		conn net.Conn
	)
	if s.proxyDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
		conn, err = net.DialTimeout(p.Protocol.String(), hostport, timeout)
	}
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// udp needs data probe
	switch p.Protocol {
	case protocol.UDP:
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return false, err
		}
		if _, err := conn.Write(nil); err != nil {
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
	}

	return true, err
}
