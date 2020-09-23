package scan

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingIcmpEchoRequest syncronous to the target ip address
func PingIcmpEchoRequest(ip string, timeout time.Duration) bool {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte(""),
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}

	n, err := c.WriteTo(data, destAddr)
	if err != nil {
		return false
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	n, sourceIp, err := c.ReadFrom(reply)
	// timeout
	if err != nil {
		return false
	}
	// if anything is read from the connection it means that the host is alive
	if destAddr.String() == sourceIp.String() && n > 0 {
		return true
	}

	return false
}

// PingIcmpEchoRequestAsync asyncronous to the target ip address
func (s *Scanner) PingIcmpEchoRequestAsync(ip string) {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Data: []byte(""),
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return
	}
	retries := 0
send:
	if retries >= 10 {
		return
	}
	_, err = s.icmpPacketListener.WriteTo(data, destAddr)
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(10) * time.Millisecond)
		goto send
	}
}

// PingIcmpTimestampRequest syncronous to the target ip address
func PingIcmpTimestampRequest(ip string, timeout time.Duration) bool {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer c.Close()

	m := icmp.Message{
		Type: ipv4.ICMPTypeTimestamp,
		Code: 0,
		Body: &Timestamp{
			ID:              os.Getpid() & 0xffff,
			Seq:             0,
			OriginTimestamp: 0,
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}

	n, err := c.WriteTo(data, destAddr)
	if err != nil {
		return false
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	n, sourceIp, err := c.ReadFrom(reply)
	// timeout
	if err != nil {
		return false
	}
	// if anything is read from the connection it means that the host is alive
	if destAddr.String() == sourceIp.String() && n > 0 {
		return true
	}

	return false
}

// PingIcmpTimestampRequestAsync syncronous to the target ip address
func (s *Scanner) PingIcmpTimestampRequestAsync(ip string) {
	destAddr := &net.IPAddr{IP: net.ParseIP(ip)}
	m := icmp.Message{
		Type: ipv4.ICMPTypeTimestamp,
		Code: 0,
		Body: &Timestamp{
			ID:              os.Getpid() & 0xffff,
			Seq:             0,
			OriginTimestamp: 0,
		},
	}

	data, err := m.Marshal(nil)
	if err != nil {
		return
	}

	s.icmpPacketListener.WriteTo(data, destAddr)
}

// Timestamp ICMP structure
type Timestamp struct {
	ID                int
	Seq               int
	OriginTimestamp   uint32
	ReceiveTimestamp  uint32
	TransmitTimestamp uint32
}

const marshalledTimestampLen = 16

// Len returns default timestamp length
func (t *Timestamp) Len(_ int) int {
	if t == nil {
		return 0
	}
	return marshalledTimestampLen
}

// Marshal the timestamp structure
func (t *Timestamp) Marshal(_ int) ([]byte, error) {
	b := make([]byte, marshalledTimestampLen)
	b[0], b[1] = byte(t.ID>>8), byte(t.ID)
	b[2], b[3] = byte(t.Seq>>8), byte(t.Seq)

	unparseInt := func(i uint32) (byte, byte, byte, byte) {
		return byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)
	}
	b[4], b[5], b[6], b[7] = unparseInt(t.OriginTimestamp)
	b[8], b[9], b[10], b[11] = unparseInt(t.ReceiveTimestamp)
	b[12], b[13], b[14], b[15] = unparseInt(t.TransmitTimestamp)
	return b, nil
}

// ParseTimestamp to MessageBody structure
func ParseTimestamp(_ int, b []byte) (icmp.MessageBody, error) {
	bodyLen := len(b)
	if bodyLen != marshalledTimestampLen {
		return nil, fmt.Errorf("timestamp body length %d not equal to 16", bodyLen)
	}
	p := &Timestamp{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}

	parseInt := func(start int) uint32 {
		return uint32(b[start])<<24 | uint32(b[start+1])<<16 | uint32(b[start+2])<<8 | uint32(b[start+3])
	}
	p.OriginTimestamp = parseInt(4)
	p.ReceiveTimestamp = parseInt(8)
	p.TransmitTimestamp = parseInt(12)
	return p, nil
}
