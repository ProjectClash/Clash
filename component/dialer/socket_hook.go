package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// SocketControl
// never change type traits because it's used in CMFA
type SocketControl func(network, address string, conn syscall.RawConn) error

// DefaultSocketHook
// never change type traits because it's used in CMFA
var DefaultSocketHook SocketControl

var SocketHookScopesInterfaceOnly bool

type AddressTransform func(network string, destination netip.Addr) (netip.Addr, error)

var DefaultAddressTransform AddressTransform

var ErrPhysicalIPv6Unavailable = errors.New("physical path does not support IPv6")

func TransformPhysicalAddress(network string, destination netip.Addr) (netip.Addr, error) {
	if DefaultAddressTransform == nil || !destination.IsValid() {
		return destination, nil
	}
	return DefaultAddressTransform(network, destination)
}

func socketHookToToDialer(dialer *net.Dialer) {
	addControlToDialer(dialer, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return DefaultSocketHook(network, address, c)
	})
}

func socketHookToListenConfig(lc *net.ListenConfig) {
	addControlToListenConfig(lc, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return DefaultSocketHook(network, address, c)
	})
}
