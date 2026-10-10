package inbound

import (
	"net"
	"net/netip"
	"sync/atomic"

	C "github.com/ProjectClash/Clash/constant"
)

var skipAuthPrefixes atomic.Pointer[[]netip.Prefix]

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	skipAuthPrefixes.Store(&prefixes)
}

func SkipAuthPrefixes() []netip.Prefix {
	return loadPrefixes(&skipAuthPrefixes)
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func SkipAuthRemoteAddress(addr string) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddress(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func skipAuth(addr netip.Addr) bool {
	return prefixesContains(SkipAuthPrefixes(), addr)
}
