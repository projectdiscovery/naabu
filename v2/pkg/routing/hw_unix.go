//go:build linux || darwin

package routing

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func GetHWWithIp(r Router, handler pcap.Handle, sourceHW net.HardwareAddr, sourceIP, destIp net.IP) (net.HardwareAddr, error) {
	// Check if there is a route with the specified network interface
	_, _, preferredSrc, err := r.RouteWithSrc(sourceHW, sourceIP, destIp)
	if err != nil {
		return nil, err
	}

	if preferredSrc != nil {
		return net.HardwareAddr(preferredSrc), nil
	}

	// obtain the destination HW with ARP request
	eth := layers.Ethernet{
		SrcMAC:       sourceHW,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(sourceHW),
		SourceProtAddress: []byte(sourceIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(destIp),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return nil, err
	}
	err = handler.WritePacketData(buf.Bytes())
	if err != nil {
		return nil, err
	}

	time.Sleep(3 * time.Second)

	s, err := lookupMACAddress(destIp.String())
	if err != nil {
		return nil, err
	}

	return net.ParseMAC(s)
}

func lookupMACAddress(ipToLookup string) (string, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error executing arp command: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ipToLookup) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("MAC Address not found for IP: %s", ipToLookup)
}
