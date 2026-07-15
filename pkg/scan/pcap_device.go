//go:build linux || darwin || windows

package scan

import (
	"net"
	"runtime"
	"strings"

	"github.com/Mzack9999/gopacket/pcap"
)

// pcapDeviceForInterface returns the device name gopacket/pcap expects for iface.
// On Windows, net.Interfaces names rarely match Npcap device paths
// (`\Device\NPF_{GUID}`), so we resolve via pcap.FindAllDevs by IP / description.
func pcapDeviceForInterface(iface *net.Interface) string {
	if iface == nil {
		return ""
	}
	if runtime.GOOS != "windows" {
		return iface.Name
	}
	if name := matchWindowsPcapDevice(iface); name != "" {
		return name
	}
	return iface.Name
}

func matchWindowsPcapDevice(iface *net.Interface) string {
	devices, err := pcap.FindAllDevs()
	if err != nil || len(devices) == 0 {
		return ""
	}

	addrs, err := iface.Addrs()
	if err != nil {
		addrs = nil
	}
	ifaceIPs := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			ifaceIPs = append(ifaceIPs, v.IP)
		case *net.IPAddr:
			ifaceIPs = append(ifaceIPs, v.IP)
		}
	}

	for _, dev := range devices {
		for _, da := range dev.Addresses {
			for _, ip := range ifaceIPs {
				if da.IP != nil && da.IP.Equal(ip) {
					return dev.Name
				}
			}
		}
	}

	// Fall back to description / partial name match when IPs are unavailable
	// (e.g. interface briefly without address).
	ifaceName := strings.ToLower(iface.Name)
	for _, dev := range devices {
		desc := strings.ToLower(dev.Description)
		if desc == ifaceName || strings.Contains(desc, ifaceName) || strings.EqualFold(dev.Name, iface.Name) {
			return dev.Name
		}
	}
	return ""
}
