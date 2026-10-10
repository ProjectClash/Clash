package clash

import (
	"net"
	"net/netip"
	"syscall"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/log"
)

func interfaceScopableTarget(address string) bool {
	if address == "" {
		return true
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			host = address
		}
		if host == "localhost" {
			return false
		}
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil {
			return true
		}
		return addr.Unmap().IsGlobalUnicast()
	}
	return addrPort.Addr().Unmap().IsGlobalUnicast()
}

var publishedInterfaceIndex = atomic.NewInt32(0)

var noPathDialsLogged atomic.Bool

func installSocketHook(platform PlatformInterface) {
	installPhysicalAddressTransform(platform != nil)
	if platform == nil || !platform.UsePlatformAutoDetectInterfaceControl() {
		dialer.DefaultSocketHook = nil
		dialer.SocketHookScopesInterfaceOnly = false
		return
	}
	dialer.SocketHookScopesInterfaceOnly = true
	dialer.DefaultSocketHook = func(_, address string, conn syscall.RawConn) error {
		if !interfaceScopableTarget(address) {
			return nil
		}
		if publishedInterfaceIndex.Load() == 0 {
			if noPathDialsLogged.CompareAndSwap(false, true) {
				log.Warnln("[Apple] no physical path is published; outbound sockets dial unbound until one is, rather than failing")
			}
			return nil
		}
		noPathDialsLogged.Store(false)
		var ctrlErr error
		if err := conn.Control(func(fd uintptr) {
			ctrlErr = platform.AutoDetectInterfaceControl(int32(fd))
		}); err != nil {
			return err
		}
		return ctrlErr
	}
}
