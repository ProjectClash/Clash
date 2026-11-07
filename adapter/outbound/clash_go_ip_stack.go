package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
)

type IPStack interface {
	Start() error
	DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	DialIP(ctx context.Context, network string, source, destination netip.Addr) (net.Conn, error)
	ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error)
	ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error)
	ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error)
	Read(buffers [][]byte, sizes []int, offset int) (int, error)
	Write(buffers [][]byte, offset int) (int, error)
	MTU() (int, error)
	Name() (string, error)
	BatchSize() int
	Close() error
}

type ipStack = IPStack

var IPStackCongestionControllers = []string{"bbr", "bbr3", "cubic", "reno"}

type GoIPStackOptions struct {
	LocalAddresses       []netip.Prefix
	MTU                  uint32
	CongestionController string
}

type GoIPStackFactory func(options GoIPStackOptions) (IPStack, error)

var goIPStackFactory atomic.Pointer[GoIPStackFactory]

func SetGoIPStackFactory(factory GoIPStackFactory) {
	if factory == nil {
		goIPStackFactory.Store(nil)
		return
	}
	goIPStackFactory.Store(&factory)
}

var errNoIPStack = errors.New("this build has no IP stack for WireGuard, MASQUE, OpenVPN or ZeroTier nodes")

func newIPStack(option IPStackOption, localAddresses []netip.Prefix, mtu uint32) (ipStack, error) {
	if err := validateIPStackSettings(localAddresses, mtu); err != nil {
		return nil, err
	}
	factory := goIPStackFactory.Load()
	if factory == nil {
		return nil, errNoIPStack
	}
	return (*factory)(GoIPStackOptions{
		LocalAddresses:       localAddresses,
		MTU:                  mtu,
		CongestionController: option.CongestionController,
	})
}

func validateIPStackSettings(localPrefixes []netip.Prefix, mtu uint32) error {
	if mtu != 0 && (mtu < 68 || mtu > 65535) {
		return fmt.Errorf("invalid IP stack MTU %d; expected 68 to 65535", mtu)
	}
	for i, prefix := range localPrefixes {
		for _, other := range localPrefixes[i+1:] {
			if prefix.Addr() == other.Addr() {
				return fmt.Errorf("duplicate IP stack local address %s", prefix.Addr())
			}
		}
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return fmt.Errorf("invalid IP stack local address %s", prefix)
		}
		bits := prefix.Bits()
		if prefix.Addr().Is6() && address.Is4() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return fmt.Errorf("invalid IP stack local prefix %s", prefix)
		}
		if address.Is4() && clashIPv4MayBeBroadcast(address, bits) {
			return fmt.Errorf("IP stack local address %s is a broadcast address", prefix)
		}
	}
	for i, prefix := range localPrefixes {
		address := prefix.Addr().Unmap()
		if !address.Is4() {
			continue
		}
		for j, other := range localPrefixes {
			otherAddress := other.Addr().Unmap()
			bits := other.Bits()
			if other.Addr().Is6() && otherAddress.Is4() {
				bits -= 96
			}
			if i == j || !otherAddress.Is4() || bits < 0 || bits >= 31 {
				continue
			}
			if network, err := otherAddress.Prefix(bits); err == nil && network.Contains(address) && clashIPv4MayBeBroadcast(address, bits) {
				return fmt.Errorf("IP stack local address %s is the broadcast address of %s", prefix.Addr(), other)
			}
		}
	}
	return nil
}
