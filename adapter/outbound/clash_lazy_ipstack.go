package outbound

import (
	"net/netip"
)

func clashIPStackMayRefuse(localPrefixes []netip.Prefix, mtu uint32) bool {
	if mtu != 0 && (mtu < 68 || mtu > 65535) {
		return true
	}
	for i, prefix := range localPrefixes {
		for _, other := range localPrefixes[i+1:] {
			if prefix.Addr() == other.Addr() {
				return true
			}
		}
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return true
		}
		bits := prefix.Bits()
		if prefix.Addr().Is6() && address.Is4() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return true
		}
		if address.Is4() && clashIPv4MayBeBroadcast(address, bits) {
			return true
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
				return true
			}
		}
	}
	return false
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
