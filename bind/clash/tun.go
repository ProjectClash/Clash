package clash

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	LC "github.com/ProjectClash/Clash/listener/config"
	singtun "github.com/metacubex/sing-tun"
)

const (
	defaultTunMTU int32 = 4064
	minimumTunMTU int32 = 1280
	maximumTunMTU int32 = 9000
)

var setupTunMTU atomic.Int32

func validateTunMTU(mtu int) error {
	if mtu == 0 {
		return nil
	}
	if mtu < int(minimumTunMTU) || mtu > int(maximumTunMTU) {
		return fmt.Errorf("clash: SetupOptions.TunMTU must be 0 or %d...%d, got %d", minimumTunMTU, maximumTunMTU, mtu)
	}
	return nil
}

func setTunMTU(mtu int32) {
	if mtu == 0 {
		mtu = defaultTunMTU
	}
	setupTunMTU.Store(mtu)
}

func normalizedTunMTU(mtu int) int32 {
	if mtu == 0 {
		return defaultTunMTU
	}
	return int32(mtu)
}

func effectiveTunMTU() int32 {
	if mtu := setupTunMTU.Load(); mtu != 0 {
		return mtu
	}
	return defaultTunMTU
}

const packetFlowBridgeDevice = "clash-packet-flow"

func TunMTU() int32 {
	return effectiveTunMTU()
}

type TunOptions interface {
	GetIPv6Mode() string
	GetInet4Address() RoutePrefixIterator
	GetInet6Address() RoutePrefixIterator
	GetDNSServerAddress() (*StringBox, error)
	GetMTU() int32
	GetAutoRoute() bool
	GetStrictRoute() bool
	GetInet4RouteAddress() RoutePrefixIterator
	GetInet6RouteAddress() RoutePrefixIterator
	GetInet4RouteExcludeAddress() RoutePrefixIterator
	GetInet6RouteExcludeAddress() RoutePrefixIterator
	GetInet4LoopbackAddress() RoutePrefixIterator
	GetInet6LoopbackAddress() RoutePrefixIterator
}

type tunOptions struct {
	ipv6Mode string
	tun      *LC.Tun
}

func newTunOptions(tun *LC.Tun) TunOptions {
	return &tunOptions{tun: tun, ipv6Mode: currentIPStackSettings().tunIPv6Mode}
}

func (o *tunOptions) GetIPv6Mode() string { return o.ipv6Mode }

func (o *tunOptions) GetInet4Address() RoutePrefixIterator {
	return mapRoutePrefix(o.tun.Inet4Address)
}

func (o *tunOptions) GetInet6Address() RoutePrefixIterator {
	return mapRoutePrefix(o.tun.Inet6Address)
}

func (o *tunOptions) GetDNSServerAddress() (*StringBox, error) {
	if len(o.tun.Inet4Address) == 0 || o.tun.Inet4Address[0].Bits() == 32 {
		return nil, errors.New("clash: need one more IPv4 address for DNS hijacking")
	}
	return WrapString(o.tun.Inet4Address[0].Addr().Next().String()), nil
}

func (o *tunOptions) GetMTU() int32 {
	if o.tun.MTU == 0 {
		return effectiveTunMTU()
	}
	return int32(o.tun.MTU)
}

func (o *tunOptions) GetAutoRoute() bool {
	return o.tun.AutoRoute
}

func (o *tunOptions) GetStrictRoute() bool {
	return o.tun.StrictRoute
}

func (o *tunOptions) GetInet4RouteAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet4RouteAddress, o.tun.RouteAddress, true))
}

func (o *tunOptions) GetInet6RouteAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet6RouteAddress, o.tun.RouteAddress, false))
}

func (o *tunOptions) GetInet4RouteExcludeAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet4RouteExcludeAddress, o.tun.RouteExcludeAddress, true))
}

func (o *tunOptions) GetInet6RouteExcludeAddress() RoutePrefixIterator {
	return mapRoutePrefix(routePrefixesByFamily(o.tun.Inet6RouteExcludeAddress, o.tun.RouteExcludeAddress, false))
}

func (o *tunOptions) GetInet4LoopbackAddress() RoutePrefixIterator {
	return mapRoutePrefix(loopbackRoutes(o.tun.LoopbackAddress, true))
}

func (o *tunOptions) GetInet6LoopbackAddress() RoutePrefixIterator {
	return mapRoutePrefix(loopbackRoutes(o.tun.LoopbackAddress, false))
}

func loopbackRoutes(addresses []netip.Addr, ipv4 bool) []netip.Prefix {
	var routes []netip.Prefix
	for _, address := range singtun.LoopbackAddresses(addresses, nil) {
		if address.Is4() == ipv4 {
			routes = append(routes, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return routes
}

func routePrefixesByFamily(specific, generic []netip.Prefix, ipv4 bool) []netip.Prefix {
	routes := append([]netip.Prefix(nil), specific...)
	for _, prefix := range generic {
		if prefix.Addr().Is4() == ipv4 {
			routes = append(routes, prefix)
		}
	}
	return routes
}
