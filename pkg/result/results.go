package result

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/result/confidence"
	"golang.org/x/exp/maps"
)

type ResultFn func(*HostResult)

type OSFingerprint struct {
	Target     string
	DeviceType string
	Running    string
	OSCPE      string
	OSDetails  string
}

type HostResult struct {
	Host       string
	IP         string
	Ports      []*port.Port
	Confidence confidence.ConfidenceLevel
	OS         *OSFingerprint
	MacAddress string
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
			confidenceLevel := confidence.Normal
			if r.HasSkipped(ip) {
				confidenceLevel = confidence.Low
			}

			hostResult := &HostResult{IP: ip, Ports: maps.Values(ports), Confidence: confidenceLevel}

			// Perform ARP lookup for private/local network IPs
			if isPrivateIP(ip) {
				if macAddr, err := GetMacAddress(ip); err == nil {
					hostResult.MacAddress = macAddr
				}
			}

			out <- hostResult
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

// UpdateHostOS updates the OS info for a given IP in the results
func (r *Result) UpdateHostOS(ip string, osfp *OSFingerprint) {
	for hostResult := range r.GetIPsPorts() {
		if hostResult.IP == ip {
			hostResult.OS = osfp
			return
		}
	}
}

// isPrivateIP checks if an IP address is in a private/local network range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

// GetMacAddress retrieves the MAC address for a given target (IP address or hostname).
// It resolves hostnames to IP addresses first, then queries the ARP table.
// Returns an empty string if the MAC address cannot be found.
func GetMacAddress(target string) (string, error) {
	// Resolve hostname to IP if needed
	ip := target
	if net.ParseIP(target) == nil {
		// Not a valid IP, try to resolve as hostname
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("failed to resolve hostname %s: %w", target, err)
		}
		// Use the first IPv4 address if available, otherwise use the first address
		for _, addr := range ips {
			if addr.To4() != nil {
				ip = addr.String()
				break
			}
		}
		if ip == target {
			ip = ips[0].String()
		}
	}

	// Determine ARP command arguments based on OS
	var arpArgs []string
	switch runtime.GOOS {
	case "linux", "darwin":
		// Linux and macOS use the same command format
		arpArgs = []string{"-n", ip}
	case "windows":
		// Windows uses different arguments
		arpArgs = []string{"-a", ip}
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Query ARP table
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arp", arpArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute arp command: %w", err)
	}

	// Parse ARP output to find MAC address
	outputStr := string(output)

	// Windows output is line-based, so check each line for the IP
	if runtime.GOOS == "windows" {
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, ip) {
				for _, field := range strings.FieldsFunc(line, unicode.IsSpace) {
					if mac, err := net.ParseMAC(field); err == nil {
						return mac.String(), nil
					}
				}
			}
		}
	} else {
		// Linux and macOS: parse all fields in the output
		for _, field := range strings.FieldsFunc(outputStr, unicode.IsSpace) {
			if mac, err := net.ParseMAC(field); err == nil {
				return mac.String(), nil
			}
		}
	}

	return "", fmt.Errorf("MAC address not found in ARP table for %s", ip)
}
