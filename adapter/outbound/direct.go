package outbound

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/loopback"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
)

type Direct struct {
	*Base
	loopBack *loopback.Detector
}

type DirectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := d.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	opts := d.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), opts...)
	if err != nil {
		return nil, err
	}
	return d.loopBack.NewConn(NewConn(c, d)), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := d.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := d.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	physicalDestination, err := dialer.TransformPhysicalAddress("udp", metadata.DstIP)
	if err != nil {
		ip, fallbackErr := physicalIPv4Fallback(ctx, metadata.Host, d.prefer, resolver.DirectHostResolver, err)
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		metadata.DstIP = ip
		physicalDestination, err = dialer.TransformPhysicalAddress("udp", ip)
		if err != nil {
			return nil, err
		}
	}
	logicalRemote := metadata.AddrPort()
	physicalRemote := netip.AddrPortFrom(physicalDestination, metadata.DstPort)
	pc, err := dialer.NewDialer(d.DialOptions()...).ListenPacket(ctx, "udp", "", physicalRemote)
	if err != nil {
		return nil, err
	}
	if physicalRemote != logicalRemote {
		pc = newPhysicalAddressPacketConn(pc, logicalRemote, physicalRemote)
	}
	return d.loopBack.NewPacketConn(NewPacketConn(pc, d)), nil
}

func (d *Direct) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	policy := resolver.CurrentIPQueryPolicy()
	explicit := policy != resolver.IPQueryLegacy
	if explicit && ((policy == resolver.IPQueryIPv4Only && d.prefer == C.IPv6Only) || (policy == resolver.IPQueryIPv6Only && d.prefer == C.IPv4Only)) {
		return resolver.ErrIPVersion
	}
	familyMismatch := explicit && metadata.DstIP.IsValid() && (!policy.AllowsAddress(metadata.DstIP) || (d.prefer == C.IPv4Only && !metadata.DstIP.Unmap().Is4()) || (d.prefer == C.IPv6Only && !metadata.DstIP.Unmap().Is6()))
	if (!metadata.Resolved() || resolver.DirectHostResolver != resolver.DefaultResolver || familyMismatch) && metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, d.prefer, resolver.DirectHostResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	if explicit && (!policy.AllowsAddress(metadata.DstIP) || (d.prefer == C.IPv4Only && !metadata.DstIP.Unmap().Is4()) || (d.prefer == C.IPv6Only && !metadata.DstIP.Unmap().Is6())) {
		return resolver.ErrIPVersion
	}
	return nil
}

func (d *Direct) IsL3Protocol(metadata *C.Metadata) bool {
	return true // tell DNSDialer don't send domain to DialContext, avoid lookback to DefaultResolver
}

func NewDirectWithOption(option DirectOption) *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Direct,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewDirect() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "DIRECT",
			Type:   C.Direct,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewCompatible() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "COMPATIBLE",
			Type:   C.Compatible,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}
