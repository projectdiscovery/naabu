package result

import (
	"sync"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"golang.org/x/exp/maps"
)

type HostResult struct {
	Host  string
	IP    string
	Ports []*port.Port
}

// Result of the scan
type Result struct {
	sync.RWMutex
	ipPorts map[string]map[string]*port.Port
	ips     map[string]struct{}
	skipped map[string]struct{}
}

// NewResult structure
func NewResult() *Result {
	ipPorts := make(map[string]map[string]*port.Port)
	ips := make(map[string]struct{})
	skipped := make(map[string]struct{})
	return &Result{ipPorts: ipPorts, ips: ips, skipped: skipped}
}

// AddPort to a specific ip
func (r *Result) GetIPs() chan string {
	r.Lock()

	out := make(chan string)

	go func() {
		defer close(out)
		defer r.Unlock()

		for ip := range r.ips {
			out <- ip
		}
	}()

	return out
}

func (r *Result) HasIPS() bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.ips) > 0
}

// GetIpsPorts returns the ips and ports
func (r *Result) GetIPsPorts() chan *HostResult {
	r.RLock()

	out := make(chan *HostResult)

	go func() {
		defer close(out)
		defer r.RUnlock()

		for ip, ports := range r.ipPorts {
			if r.HasSkipped(ip) {
				continue
			}
			out <- &HostResult{IP: ip, Ports: maps.Values(ports)}
		}
	}()

	return out
}

func (r *Result) HasIPsPorts() bool {
	r.RLock()
	defer r.RUnlock()

	return len(r.ipPorts) > 0
}

// AddPort to a specific ip
func (r *Result) AddPort(ip string, p *port.Port) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.ipPorts[ip]; !ok {
		r.ipPorts[ip] = make(map[string]*port.Port)
	}

	r.ipPorts[ip][p.String()] = p
	r.ips[ip] = struct{}{}
}

// SetPorts for a specific ip
func (r *Result) SetPorts(ip string, ports []*port.Port) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.ipPorts[ip]; !ok {
		r.ipPorts[ip] = make(map[string]*port.Port)
	}

	for _, p := range ports {
		r.ipPorts[ip][p.String()] = p
	}
	r.ips[ip] = struct{}{}
}

// IPHasPort checks if an ip has a specific port
func (r *Result) IPHasPort(ip string, p *port.Port) bool {
	r.RLock()
	defer r.RUnlock()

	ipPorts, hasports := r.ipPorts[ip]
	if !hasports {
		return false
	}
	_, hasport := ipPorts[p.String()]

	return hasport
}

// AddIp adds an ip to the results
func (r *Result) AddIp(ip string) {
	r.Lock()
	defer r.Unlock()

	r.ips[ip] = struct{}{}
}

// HasIP checks if an ip has been seen
func (r *Result) HasIP(ip string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.ips[ip]
	return ok
}

func (r *Result) IsEmpty() bool {
	return r.Len() == 0
}

func (r *Result) Len() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.ips)
}

// GetPortCount returns the number of ports discovered for an ip
func (r *Result) GetPortCount(host string) int {
	r.RLock()
	defer r.RUnlock()

	return len(r.ipPorts[host])
}

// AddSkipped adds an ip to the skipped list
func (r *Result) AddSkipped(ip string) {
	r.Lock()
	defer r.Unlock()

	r.skipped[ip] = struct{}{}
}

// HasSkipped checks if an ip has been skipped
func (r *Result) HasSkipped(ip string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.skipped[ip]
	return ok
}
