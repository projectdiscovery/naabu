// +build windows netbsd openbsd dragonfly plan9 freebsd

package scan

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
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
	NetworkInterface *net.Interface
	SourceIP         net.IP
	retries          int
	rate             int
	timeout          time.Duration

	Ports    []int
	IPRanger *ipranger.IPRanger

	State       State
	ScanResults *result.Result
	cdn         *cdncheck.Client
	debug       bool
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
		timeout:  options.Timeout,
		retries:  options.Retries,
		rate:     options.Rate,
		debug:    options.Debug,
		IPRanger: iprang,
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

// ConnectPort a single host and port
func ConnectPort(host string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, err
}

// TuneSource automatically with ip and interface
func (s *Scanner) TuneSource(ip string) error {
	return nil
}

// SetupHandlers to listen on all interfaces
func (s *Scanner) SetupHandlers() error {
	return nil
}

// StartWorkers of the scanner
func (s *Scanner) StartWorkers() {
}

// EnqueueTCP outgoing TCP packets
func (s *Scanner) EnqueueTCP(ip string, port int, pkgtype PkgFlag) {

}
