//go:build darwin

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"github.com/metacubex/sing/common/logger"
	"golang.org/x/sys/unix"
)


const bindListenerSupported = true

var errTunAddressNotPresent = fmt.Errorf("no up interface carries the tun address yet: %w", unix.EADDRNOTAVAIL)

var (
	enumerateInterfaces = net.Interfaces
	interfaceAddresses  = (*net.Interface).Addrs
)

func interfaceIndexCarrying(addr netip.Addr) (index int, carriers int, err error) {
	index = -1
	if !addr.IsValid() {
		return index, 0, nil
	}
	want := addr.Unmap()
	interfaces, err := enumerateInterfaces()
	if err != nil {
		return index, 0, fmt.Errorf("enumerate interfaces: %w: %w", err, unix.EADDRNOTAVAIL)
	}
	for i := range interfaces {
		iface := &interfaces[i]
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, addrsErr := interfaceAddresses(iface)
		if addrsErr != nil {
			continue
		}
		for _, ifaceAddr := range addresses {
			var got netip.Addr
			switch typed := ifaceAddr.(type) {
			case *net.IPNet:
				got, _ = netip.AddrFromSlice(typed.IP)
			case *net.IPAddr:
				got, _ = netip.AddrFromSlice(typed.IP)
			}
			if got.Unmap() == want {
				carriers++
				if iface.Index > index {
					index = iface.Index
				}
				break
			}
		}
	}
	return index, carriers, nil
}

func bindListenerToInterfaceControl(index int, log logger.Logger) func(network, address string, conn syscall.RawConn) error {
	if index < 0 {
		return nil
	}
	return func(network, _ string, conn syscall.RawConn) error {
		var opErr error
		controlErr := conn.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			} else {
				opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			}
		})
		if controlErr != nil {
			return controlErr
		}
		if opErr != nil {
			log.Warn("[bindif] setsockopt bound-if index ", index, ": ", opErr)
			return fmt.Errorf("bind %s listener to interface index %d: %w: %w", network, index, opErr, unix.EADDRNOTAVAIL)
		}
		return nil
	}
}
