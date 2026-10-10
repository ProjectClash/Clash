package outbound

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/proxydialer"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"net/netip"
	"testing"
)

func TestIPStackUDPNodePreferenceCannotRelaxGlobalRestriction(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv4Only)
	if _, err := resolveIPWithResolver(context.Background(), "2001:db8::1", C.IPv6Only, nil); !errors.Is(err, resolver.ErrIPVersion) {
		t.Fatal(err)
	}
	ip, err := resolveIPWithResolver(context.Background(), "192.0.2.1", C.IPv6Prefer, nil)
	if err != nil || ip != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("%v %v", ip, err)
	}
}

func TestIPStackDirectUDPRejectsOnlyConflictForResolvedAndDomainTargets(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	for _, tc := range []struct {
		global  resolver.IPQueryPolicy
		node    C.DNSPrefer
		address string
	}{{resolver.IPQueryIPv4Only, C.IPv6Only, "192.0.2.1"}, {resolver.IPQueryIPv6Only, C.IPv4Only, "2001:db8::1"}} {
		resolver.SetIPQueryPolicy(tc.global)
		direct := NewDirectWithOption(DirectOption{BasicOption: BasicOption{IPVersion: tc.node}, Name: "only"})
		for _, host := range []string{"", "stack.example"} {
			metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr(tc.address), DstPort: 443, Host: host}
			if err := direct.ResolveUDP(context.Background(), metadata); !errors.Is(err, resolver.ErrIPVersion) {
				t.Fatalf("ResolveUDP host=%q: %v", host, err)
			}
			if conn, err := direct.ListenPacketContext(context.Background(), metadata); !errors.Is(err, resolver.ErrIPVersion) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("ListenPacket host=%q: %v", host, err)
			}
		}
	}
}

type stackPhysicalResolver struct {
	resolver.Resolver
	ipv6Rejected <-chan struct{}
}

func (r stackPhysicalResolver) Invalid() bool { return true }
func (r stackPhysicalResolver) LookupIPv4(ctx context.Context, _ string) ([]netip.Addr, error) {
	select {
	case <-r.ipv6Rejected:
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (r stackPhysicalResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
}
func TestIPStackUDPUsesAllowedIPv4WhenPhysicalPathHasNoIPv6(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	oldResolver, oldTransform := resolver.ProxyServerHostResolver, dialer.DefaultAddressTransform
	defer func() { resolver.ProxyServerHostResolver = oldResolver; dialer.DefaultAddressTransform = oldTransform }()
	resolver.SetIPQueryPolicy(resolver.IPQueryDualStack)
	rejected := make(chan struct{})
	resolver.ProxyServerHostResolver = stackPhysicalResolver{ipv6Rejected: rejected}
	calls := 0
	dialer.DefaultAddressTransform = func(_ string, ip netip.Addr) (netip.Addr, error) {
		calls++
		if ip.Is6() {
			close(rejected)
			return netip.Addr{}, dialer.ErrPhysicalIPv6Unavailable
		}
		return ip, nil
	}
	got, err := resolveUDPAddr(context.Background(), "udp", "peer.example:443", C.DualStack)
	if err != nil || got.AddrPort().Addr() != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("%v %v", got, err)
	}
	if calls != 2 {
		t.Fatalf("transform repeated: %d", calls)
	}
	if _, err := physicalIPv4Fallback(context.Background(), "2001:db8::1", C.DualStack, resolver.ProxyServerHostResolver, dialer.ErrPhysicalIPv6Unavailable); err == nil {
		t.Fatal("literal IPv6 target silently replaced")
	}
	if _, err := physicalIPv4Fallback(context.Background(), "peer.example", C.IPv6Only, resolver.ProxyServerHostResolver, dialer.ErrPhysicalIPv6Unavailable); err == nil {
		t.Fatal("node only constraint relaxed")
	}
}

type stackDirectOnlyResolver struct {
	resolver.Resolver
	address netip.Addr
}

func (r stackDirectOnlyResolver) Invalid() bool { return true }
func (r stackDirectOnlyResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	if !r.address.IsValid() {
		return nil, resolver.ErrIPNotFound
	}
	return []netip.Addr{r.address}, nil
}
func TestIPStackDirectUDPUsesDirectNameserverDespiteDefaultFailure(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	oldDefault, oldDirect := resolver.DefaultResolver, resolver.DirectHostResolver
	defer func() { resolver.DefaultResolver = oldDefault; resolver.DirectHostResolver = oldDirect }()
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv4Only)
	resolver.DefaultResolver = stackDirectOnlyResolver{}
	want := netip.MustParseAddr("192.0.2.9")
	resolver.DirectHostResolver = stackDirectOnlyResolver{address: want}
	metadata := &C.Metadata{Host: "internal.example", NetWork: C.UDP, DstPort: 443}
	if err := NewDirect().ResolveUDP(context.Background(), metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.DstIP != want {
		t.Fatalf("direct-nameserver lost: %v", metadata.DstIP)
	}
}

type stackLogicalProxySpy struct {
	C.ProxyAdapter
	destination netip.Addr
	err         error
}

func (p *stackLogicalProxySpy) ListenPacketContext(_ context.Context, m *C.Metadata) (C.PacketConn, error) {
	p.destination = m.DstIP
	return nil, p.err
}
func TestIPStackShadowsocksIPv6PeerCanBeCarriedByAnotherProxy(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	oldTransform := dialer.DefaultAddressTransform
	defer func() { dialer.DefaultAddressTransform = oldTransform }()
	resolver.SetIPQueryPolicy(resolver.IPQueryDualStack)
	calls := 0
	dialer.DefaultAddressTransform = func(string, netip.Addr) (netip.Addr, error) {
		calls++
		return netip.Addr{}, dialer.ErrPhysicalIPv6Unavailable
	}
	reached := errors.New("proxy received logical peer")
	proxy := &stackLogicalProxySpy{err: reached}
	carrier := proxydialer.New(proxy, false)
	ss := &ShadowSocks{Base: &Base{addr: "[2001:db8::1]:443", dialer: carrier, prefer: C.DualStack}}
	_, _, err := ss.listenPacketContext(context.Background())
	if !errors.Is(err, reached) || proxy.destination != netip.MustParseAddr("2001:db8::1") || calls != 0 {
		t.Fatalf("logical peer refused/rewritten: %v %v transforms=%d", err, proxy.destination, calls)
	}
	if dialer.IsPhysicalDialer(carrier) || !dialer.IsPhysicalDialer(dialer.NewDialer()) {
		t.Fatal("physical boundary misclassified")
	}
}
