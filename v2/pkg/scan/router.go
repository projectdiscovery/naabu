package scan

import "net"

// taken from gopacket
type Router interface {
	// Route returns where to route a packet based on the packet's source
	// and destination IP address.
	//
	// Callers may pass in nil for src, in which case the src is treated as
	// either 0.0.0.0 or ::, depending on whether dst is a v4 or v6 address.
	//
	// It returns the interface on which to send the packet, the gateway IP
	// to send the packet to (if necessary), the preferred src IP to use (if
	// available).  If the preferred src address is not given in the routing
	// table, the first IP address of the interface is provided.
	//
	// If an error is encountered, iface, geteway, and
	// preferredSrc will be nil, and err will be set.
	Route(dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error)

	// RouteWithSrc routes based on source information as well as destination
	// information.  Either or both of input/src can be nil.  If both are, this
	// should behave exactly like Route(dst)
	RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (iface *net.Interface, gateway, preferredSrc net.IP, err error)
}
