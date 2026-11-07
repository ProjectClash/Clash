package outbound

import (
	"net/netip"
)

func clashIPStackMayRefuse(localPrefixes []netip.Prefix, mtu uint32) bool {
	return validateIPStackSettings(localPrefixes, mtu) != nil
}

func clashIPv4MayBeBroadcast(address netip.Addr, bits int) bool {
	value := address.As4()
	all := uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
	if all == ^uint32(0) {
		return true
	}
	if bits >= 31 {
		return false
	}
	hostMask := uint32((uint64(1) << (32 - bits)) - 1)
	return all&hostMask == hostMask
}
