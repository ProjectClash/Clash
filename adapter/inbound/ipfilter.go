package inbound

import (
	"net"
	"net/netip"
	"sync/atomic"

	C "github.com/ProjectClash/Clash/constant"
)

var lanAllowedIPs, lanDisAllowedIPs atomic.Pointer[[]netip.Prefix]

func SetAllowedIPs(prefixes []netip.Prefix) {
	lanAllowedIPs.Store(&prefixes)
}

func SetDisAllowedIPs(prefixes []netip.Prefix) {
	lanDisAllowedIPs.Store(&prefixes)
}

func loadPrefixes(p *atomic.Pointer[[]netip.Prefix]) []netip.Prefix {
	if prefixes := p.Load(); prefixes != nil {
		return *prefixes
	}
	return nil
}

func AllowedIPs() []netip.Prefix {
	return loadPrefixes(&lanAllowedIPs)
}

func DisAllowedIPs() []netip.Prefix {
	return loadPrefixes(&lanDisAllowedIPs)
}

func IsRemoteAddrDisAllowed(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	ipAddr := m.AddrPort().Addr()
	if ipAddr.IsValid() {
		return isAllowed(ipAddr) && !isDisAllowed(ipAddr)
	}
	return false
}

func isAllowed(addr netip.Addr) bool {
	return prefixesContains(AllowedIPs(), addr)
}

func isDisAllowed(addr netip.Addr) bool {
	return prefixesContains(DisAllowedIPs(), addr)
}
