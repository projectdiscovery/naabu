package scan

import (
	"net"

	"github.com/yl2chen/cidranger"
)

func AddToRanger(ipranger cidranger.Ranger, ipcidr string) error {
	// if it's an ip convert it to cidr representation
	if IsIP(ipcidr) {
		ipcidr += "/32"
	}
	// Check if it's a cidr
	_, network, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return err
	}
	return ipranger.Insert(cidranger.NewBasicRangerEntry(*network))
}

func RangerContains(ipranger cidranger.Ranger, ipcidr string) bool {
	contains, err := ipranger.Contains(net.ParseIP(ipcidr))
	return contains && err == nil
}
