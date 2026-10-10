package outbound

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/transport/socks5"
)

func serializesSocksAddr(metadata *C.Metadata) []byte {
	var buf [][]byte
	addrType := metadata.AddrType()
	p := uint(metadata.DstPort)
	port := []byte{uint8(p >> 8), uint8(p & 0xff)}
	switch addrType {
	case C.AtypDomainName:
		lenM := uint8(len(metadata.Host))
		host := []byte(metadata.Host)
		buf = [][]byte{{socks5.AtypDomainName, lenM}, host, port}
	case C.AtypIPv4:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{socks5.AtypIPv4}, host, port}
	case C.AtypIPv6:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{socks5.AtypIPv6}, host, port}
	}
	return bytes.Join(buf, nil)
}

func resolveIPWithResolver(ctx context.Context, host string, prefer C.DNSPrefer, r resolver.Resolver) (netip.Addr, error) {
	if p := resolver.CurrentIPQueryPolicy(); p != resolver.IPQueryLegacy {
		if (p == resolver.IPQueryIPv4Only && prefer == C.IPv6Only) || (p == resolver.IPQueryIPv6Only && prefer == C.IPv4Only) {
			return netip.Addr{}, resolver.ErrIPVersion
		}
		if p != resolver.IPQueryIPv4Only && p != resolver.IPQueryIPv6Only {
			switch prefer {
			case C.IPv4Only:
				p = resolver.IPQueryIPv4Only
			case C.IPv6Only:
				p = resolver.IPQueryIPv6Only
			case C.IPv4Prefer:
				p = resolver.IPQueryPreferIPv4
			case C.IPv6Prefer:
				p = resolver.IPQueryPreferIPv6
			}
		}
		return resolver.ResolveIPWithPolicy(ctx, host, r, p)
	}

	switch prefer {
	case C.IPv4Only:
		return resolver.ResolveIPv4WithResolver(ctx, host, r)
	case C.IPv6Only:
		return resolver.ResolveIPv6WithResolver(ctx, host, r)
	case C.IPv6Prefer:
		return resolver.ResolveIPPrefer6WithResolver(ctx, host, r)
	default:
		return resolver.ResolveIPWithResolver(ctx, host, r)
	}
}

func resolveUDPAddr(ctx context.Context, network, address string, prefer C.DNSPrefer, physicalPeer ...bool) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ip, err := resolveIPWithResolver(ctx, host, prefer, resolver.ProxyServerHostResolver)

	if err != nil {
		return nil, err
	}

	ip, port = resolver.LookupIP4P(ip, port)
	physical := ip
	if len(physicalPeer) == 0 || physicalPeer[0] || resolver.CurrentIPQueryPolicy() == resolver.IPQueryLegacy {
		physical, err = dialer.TransformPhysicalAddress(network, ip)
		if errors.Is(err, dialer.ErrPhysicalIPv6Unavailable) {
			ip, err = physicalIPv4Fallback(ctx, host, prefer, resolver.ProxyServerHostResolver, err)
			if err != nil {
				return nil, err
			}
			physical, err = dialer.TransformPhysicalAddress(network, ip)
		}
		if err != nil {
			return nil, err
		}
	}
	ip = physical

	var uint16Port uint16
	if port, err := strconv.ParseUint(port, 10, 16); err == nil {
		uint16Port = uint16(port)
	} else {
		return nil, err
	}
	// our resolver always unmap before return, so unneeded unmap at here
	// which is different with net.ResolveUDPAddr maybe return 4in6 address
	// 4in6 addresses can cause some strange effects on sing-based code
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16Port)), nil
}

func safeConnClose(c net.Conn, err error) {
	if err != nil && c != nil {
		_ = c.Close()
	}
}

func physicalIPv4Fallback(ctx context.Context, host string, prefer C.DNSPrefer, r resolver.Resolver, cause error) (netip.Addr, error) {
	p := resolver.CurrentIPQueryPolicy()
	if !errors.Is(cause, dialer.ErrPhysicalIPv6Unavailable) || p == resolver.IPQueryLegacy || p == resolver.IPQueryIPv6Only || prefer == C.IPv6Only || prefer == C.IPv4Only {
		return netip.Addr{}, cause
	}
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		return netip.Addr{}, cause
	}
	ip, err := resolver.ResolveIPv4WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, errors.Join(cause, err)
	}
	return ip, nil
}
