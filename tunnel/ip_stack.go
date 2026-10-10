package tunnel

import (
	"context"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"net/netip"
)

func ipStackDialMetadata(ctx context.Context, metadata *C.Metadata, resolveDomain bool) (*C.Metadata, error) {
	p := resolver.CurrentIPQueryPolicy()
	if p != resolver.IPQueryIPv4Only && p != resolver.IPQueryIPv6Only {
		return metadata, nil
	}
	copy := metadata.Clone()
	if !p.AllowsAddress(copy.DstIP) {
		return nil, resolver.ErrIPVersion
	}
	if !resolveDomain {
		return metadata, nil
	}
	if !copy.DstIP.IsValid() && copy.Host != "" {
		ip, err := resolver.ResolveIP(ctx, copy.Host)
		if err != nil {
			return nil, err
		}
		copy.DstIP = ip
	}
	if !copy.DstIP.IsValid() || !p.AllowsAddress(copy.DstIP) {
		return nil, resolver.ErrIPVersion
	}
	copy.Host = ""
	return copy, nil
}

func ipStackHostAddress(node *resolver.HostValue) (netip.Addr, error) {
	p := resolver.CurrentIPQueryPolicy()
	if p == resolver.IPQueryLegacy {
		return node.RandIP()
	}
	filtered := make([]netip.Addr, 0, len(node.IPs))
	for _, ip := range node.IPs {
		if p.AllowsAddress(ip) {
			filtered = append(filtered, ip.Unmap())
		}
	}
	if len(filtered) == 0 {
		return netip.Addr{}, resolver.ErrIPVersion
	}
	if p == resolver.IPQueryPreferIPv4 || p == resolver.IPQueryPreferIPv6 {
		preferred := make([]netip.Addr, 0, len(filtered))
		for _, ip := range filtered {
			if ip.Is4() == (p == resolver.IPQueryPreferIPv4) {
				preferred = append(preferred, ip)
			}
		}
		if len(preferred) > 0 {
			filtered = preferred
		}
	}
	copy := *node
	copy.IPs = filtered
	return copy.RandIP()
}
