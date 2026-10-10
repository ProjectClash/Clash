package dialer

import "net/netip"

func IsPhysicalGlobalIPv6(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6() && addr.IsGlobalUnicast() && !addr.IsPrivate()
}
