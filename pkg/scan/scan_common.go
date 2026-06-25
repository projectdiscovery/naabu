package scan

import (
	"errors"
	"net"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/projectdiscovery/naabu/v2/pkg/routing"
	"golang.org/x/net/icmp"
)

const (
	IPv4 = "4"
	IPv6 = "6"
)

var (
	ListenHandlers                                          []*ListenHandler
	NetworkInterface                                        string
	networkInterface                                        *net.Interface
	transportPacketSend, icmpPacketSend, ethernetPacketSend chan *PkgSend
	icmpConn4, icmpConn6                                    *icmp.PacketConn

	PkgRouter routing.Router

	ArpRequestAsync  func(ip string)
	InitScanner      func(s *Scanner) error
	NumberOfHandlers = 1
	tcpsequencer     = NewTCPSequencer()

	// listenHandlersMu guards the on-demand ListenHandlers registry against the
	// global pcap/icmp readers that iterate it concurrently with Acquire and
	// Release.
	listenHandlersMu sync.RWMutex

	// buildHandlerFn and ensureRawInfraFn are wired by the raw-socket build
	// (scan_raw.go) so Acquire here can create handlers on demand without this
	// file referencing platform-constrained symbols. They are nil on platforms
	// without raw-socket support, where Acquire falls back to a plain handler.
	buildHandlerFn   func() (*ListenHandler, error)
	ensureRawInfraFn func() bool
)

type ListenHandler struct {
	Busy                                   bool
	Phase                                  *Phase
	SourceHW                               net.HardwareAddr
	SourceIp4                              net.IP
	SourceIP6                              net.IP
	Port                                   int
	TcpConn4, UdpConn4, TcpConn6, UdpConn6 *net.IPConn
	TcpChan, UdpChan, HostDiscoveryChan    chan *PkgResult
	// UDPProbeProvider is the per-handler probe source used by the
	// raw UDP send path. It is copied here from the owning Scanner so
	// sendAsyncUDP4/6 do not need a Scanner reference; nil means "no
	// probing", which preserves the legacy zero-length-datagram
	// behavior for callers that have not opted in to -uP.
	UDPProbeProvider UDPProbeProvider
}

func NewListenHandler() *ListenHandler {
	return &ListenHandler{Phase: &Phase{}}
}

func Acquire(options *Options) (*ListenHandler, error) {
	// Privileged SYN scans get a freshly built raw-socket handler with its own
	// source port, channels and drain workers. Building on demand (rather than
	// from a fixed pre-allocated pool) means nothing is allocated until a SYN
	// scan actually runs, there is no fixed concurrency cap, and Release can
	// fully tear the handler down afterwards.
	if PkgRouter != nil && privileges.IsPrivileged && options.ScanType == TypeSyn && buildHandlerFn != nil {
		if ensureRawInfraFn != nil && !ensureRawInfraFn() {
			return nil, errors.New("could not initialize raw scan infrastructure")
		}
		h, err := buildHandlerFn()
		if err != nil {
			return nil, err
		}
		h.Busy = true
		listenHandlersMu.Lock()
		ListenHandlers = append(ListenHandlers, h)
		listenHandlersMu.Unlock()
		return h, nil
	}

	h := NewListenHandler()
	h.Busy = true
	return h, nil
}

// Release returns a handler at the end of a scan: it is removed from the
// registry the readers consult and its raw sockets are closed, which also stops
// its drain workers. Safe to call on a plain (non-raw) handler.
func (l *ListenHandler) Release() {
	listenHandlersMu.Lock()
	for i, h := range ListenHandlers {
		if h == l {
			ListenHandlers = append(ListenHandlers[:i], ListenHandlers[i+1:]...)
			break
		}
	}
	listenHandlersMu.Unlock()

	l.Busy = false
	l.Phase = &Phase{}
	l.teardown()
}

// teardown closes the handler's raw sockets. Closing the conns unblocks and
// terminates the per-handler drain goroutines started in buildListenHandler.
func (l *ListenHandler) teardown() {
	for _, c := range []*net.IPConn{l.TcpConn4, l.UdpConn4, l.TcpConn6, l.UdpConn6} {
		if c != nil {
			_ = c.Close()
		}
	}
}

func init() {
	if r, err := routing.New(); err != nil {
		gologger.Error().Msgf("could not initialize router: %s\n", err)
	} else {
		PkgRouter = r
	}
}

func ToString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}
