package result

import "sync"

// Result of the scan
type Result struct {
	sync.RWMutex
	IPPorts map[string]map[int]struct{}
	IPS     map[string]struct{}
}

// NewResult structure
func NewResult() *Result {
	ipPorts := make(map[string]map[int]struct{})
	ipDomains := make(map[string]struct{})
	return &Result{IPPorts: ipPorts, IPS: ipDomains}
}

// AddPort to a specific ip
func (r *Result) AddPort(k string, v int) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.IPPorts[k]; !ok {
		r.IPPorts[k] = make(map[int]struct{})
	}

	r.IPPorts[k][v] = struct{}{}
}

// SetPorts for a specific ip
func (r *Result) SetPorts(k string, v map[int]struct{}) {
	r.Lock()
	defer r.Unlock()

	r.IPPorts[k] = v
}

// IPHasPort checks if an ip has a specific port
func (r *Result) IPHasPort(k string, v int) bool {
	r.RLock()
	defer r.RUnlock()

	vv, hasports := r.IPPorts[k]
	if !hasports {
		return false
	}
	_, hasport := vv[v]

	return hasport
}

// SetIP as seen
func (r *Result) SetIP(ip string) {
	r.Lock()
	defer r.Unlock()

	r.IPS[ip] = struct{}{}
}

// HasIP checks if an ip has been seen
func (r *Result) HasIP(ip string) bool {
	r.RLock()
	defer r.RUnlock()

	_, ok := r.IPS[ip]
	return ok
}
