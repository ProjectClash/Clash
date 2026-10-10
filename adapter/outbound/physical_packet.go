package outbound

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/ProjectClash/Clash/component/dialer"
)

const physicalPacketReverseLimit = 64

type physicalAddressPacketConn struct {
	net.PacketConn
	mu      sync.Mutex
	reverse map[netip.AddrPort]netip.AddrPort
	keys    []netip.AddrPort
	nextKey int
}

func newPhysicalAddressPacketConn(conn net.PacketConn, logical, physical netip.AddrPort) net.PacketConn {
	return &physicalAddressPacketConn{
		PacketConn: conn,
		reverse:    map[netip.AddrPort]netip.AddrPort{physical: logical},
		keys:       []netip.AddrPort{physical},
	}
}

func (c *physicalAddressPacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	logical, ok := udpAddrPort(address)
	if !ok {
		return c.PacketConn.WriteTo(payload, address)
	}
	physicalAddress, err := dialer.TransformPhysicalAddress("udp", logical.Addr())
	if err != nil {
		return 0, err
	}
	physical := netip.AddrPortFrom(physicalAddress, logical.Port())
	if physical != logical {
		c.mu.Lock()
		if _, exists := c.reverse[physical]; !exists {
			if len(c.keys) < physicalPacketReverseLimit {
				c.keys = append(c.keys, physical)
			} else {
				oldest := c.keys[c.nextKey]
				delete(c.reverse, oldest)
				c.keys[c.nextKey] = physical
				c.nextKey = (c.nextKey + 1) % physicalPacketReverseLimit
			}
		}
		c.reverse[physical] = logical
		c.mu.Unlock()
	}
	return c.PacketConn.WriteTo(payload, net.UDPAddrFromAddrPort(physical))
}

func (c *physicalAddressPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	count, address, err := c.PacketConn.ReadFrom(payload)
	if err != nil {
		return count, address, err
	}
	physical, ok := udpAddrPort(address)
	if !ok {
		return count, address, nil
	}
	c.mu.Lock()
	logical, exists := c.reverse[physical]
	c.mu.Unlock()
	if !exists {
		return count, address, nil
	}
	return count, net.UDPAddrFromAddrPort(logical), nil
}

func (c *physicalAddressPacketConn) SyscallConn() (syscall.RawConn, error) {
	conn, ok := c.PacketConn.(syscall.Conn)
	if !ok {
		return nil, errors.New("physical packet connection does not expose syscall.Conn")
	}
	return conn.SyscallConn()
}

func udpAddrPort(address net.Addr) (netip.AddrPort, bool) {
	switch value := address.(type) {
	case *net.UDPAddr:
		return value.AddrPort(), true
	case interface{ AddrPort() netip.AddrPort }:
		return value.AddrPort(), true
	default:
		return netip.AddrPort{}, false
	}
}
