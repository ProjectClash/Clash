package sing_tun

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkTCP, N.NetworkUDP:
		return nil, h.refuseDeadIPv6AtTheDoor(network, source, destination)
	case N.NetworkICMP: // our fork only send those type to PrepareConnection now
		if !resolver.CurrentIPQueryPolicy().AllowsAddress(destination.Addr) {
			return nil, resolver.ErrIPVersion
		}
		if h.DisableICMPForwarding || h.skipPingForwardingByAddr(destination.Addr) { // skip if ICMP handling is disabled or other condition
			log.Infoln("[ICMP] %s %s --> %s using fake ping echo", network, source, destination)
			return nil, nil
		}
		log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
		directRouteDestination, err := ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)
		if err != nil {
			log.Warnln("[ICMP] failed to connect to %s", destination)
			return nil, err
		}
		log.Debugln("[ICMP] success connect to %s", destination)
		return directRouteDestination, nil
	}
	return nil, nil
}

func (h *ListenerHandler) skipPingForwardingByAddr(addr netip.Addr) bool {
	for _, prefix := range h.Inet4Address { // skip in interface ipv4 range
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range h.Inet6Address { // skip in interface ipv6 range
		if prefix.Contains(addr) {
			return true
		}
	}
	if resolver.IsFakeIP(addr) { // skip in fakeIp pool
		return true
	}
	return false
}

var pathRefusalLogged atomic.Bool

type physicalDialOracle interface {
	WouldDialPhysically(metadata *C.Metadata) bool
}

func (h *ListenerHandler) refuseDeadIPv6AtTheDoor(network string, source, destination M.Socksaddr) error {
	dst := destination.Addr
	if !dialer.IsPhysicalGlobalIPv6(dst) || resolver.IsFakeIP(dst) {
		return nil
	}
	if h.ShouldHijackDns(destination.AddrPort()) {
		return nil
	}
	if _, err := dialer.TransformPhysicalAddress(network, dst); !errors.Is(err, dialer.ErrPhysicalIPv6Unavailable) {
		pathRefusalLogged.Store(false)
		return nil
	}
	oracle, ok := h.Tunnel.(physicalDialOracle)
	if !ok {
		return nil
	}
	flow := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   source.Addr,
		SrcPort: source.Port,
		DstIP:   dst,
		DstPort: destination.Port,
	}
	if network == N.NetworkUDP {
		flow.NetWork = C.UDP
	}
	if !oracle.WouldDialPhysically(flow) {
		return nil
	}
	if pathRefusalLogged.CompareAndSwap(false, true) {
		log.Infoln("[IPv6] tun door refuses %s %s --> %s before its handshake: the physical path has no IPv6, the app falls back itself (further refusals at debug level)", network, source, destination)
	} else {
		log.Debugln("[IPv6] tun door refuses %s %s --> %s: the physical path has no IPv6", network, source, destination)
	}
	return dialer.ErrPhysicalIPv6Unavailable
}

func (h *ListenerHandler) DeferHandshake(network string, source M.Socksaddr, destination M.Socksaddr) bool {
	if network != N.NetworkTCP {
		return false
	}
	dst := destination.Addr
	for _, prefix := range h.Inet4Address {
		if prefix.Contains(dst) {
			return false
		}
	}
	for _, prefix := range h.Inet6Address {
		if prefix.Contains(dst) {
			return false
		}
	}
	return !h.ShouldHijackDns(destination.AddrPort())
}
