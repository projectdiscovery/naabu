package ipranger

import (
	"net"

	"github.com/projectdiscovery/mapcidr"
)

// IsCidr determines if the given ip is a cidr range
func IsCidr(ip string) bool {
	_, _, err := net.ParseCIDR(ip)

	return err == nil
}

// IsIP determines if the given string is a valid ip
func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Ips of a cidr
func Ips(cidr string) ([]string, error) {
	return mapcidr.IPAddresses(cidr)
}

func ToCidr(item string) *net.IPNet {
	if IsIP(item) {
		item += "/32"
	}
	if IsCidr(item) {
		_, ipnet, _ := net.ParseCIDR(item)
		return ipnet
	}
	return nil
}
