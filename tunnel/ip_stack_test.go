package tunnel

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"net/netip"
	"testing"
)

func TestIPStackStrictDestinationCannotBeRestoredAsRemoteDomain(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv4Only)
	metadata := &C.Metadata{Host: "stack.example", DstIP: netip.MustParseAddr("192.0.2.1")}
	got, err := ipStackDialMetadata(context.Background(), metadata, true)
	if err != nil || got.Host != "" || !got.DstIP.Is4() {
		t.Fatalf("%v %v", got, err)
	}
	if metadata.Host != "stack.example" {
		t.Fatal("rule/diagnostic metadata mutated")
	}
	metadata.DstIP = netip.MustParseAddr("2001:db8::1")
	if _, err := ipStackDialMetadata(context.Background(), metadata, true); !errors.Is(err, resolver.ErrIPVersion) {
		t.Fatalf("forbidden address accepted: %v", err)
	}
	if err := preHandleMetadata(metadata); !errors.Is(err, resolver.ErrIPVersion) {
		t.Fatalf("precheck lost family constraint: %v", err)
	}
}

func TestIPStackDNSAddressIsCheckedBeforeSocketOrProxy(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv4Only)
	d := NewDNSDialer(nil, nil, "")
	if _, err := d.DialContext(context.Background(), "udp", "[2001:db8::1]:53"); !errors.Is(err, resolver.ErrIPVersion) {
		t.Fatal(err)
	}
	if _, err := d.ListenPacket(context.Background(), "udp", "[2001:db8::1]:53"); !errors.Is(err, resolver.ErrIPVersion) {
		t.Fatal(err)
	}
}

type stackDirectResolver struct {
	resolver.Resolver
	address netip.Addr
}

func (r stackDirectResolver) Invalid() bool { return true }
func (r stackDirectResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	if !r.address.IsValid() {
		return nil, resolver.ErrIPNotFound
	}
	return []netip.Addr{r.address}, nil
}
func TestIPStackDirectKeepsItsOwnResolver(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	oldDefault, oldDirect := resolver.DefaultResolver, resolver.DirectHostResolver
	defer func() { resolver.DefaultResolver = oldDefault; resolver.DirectHostResolver = oldDirect }()
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv4Only)
	resolver.DefaultResolver = stackDirectResolver{}
	want := netip.MustParseAddr("192.0.2.9")
	resolver.DirectHostResolver = stackDirectResolver{address: want}
	metadata := &C.Metadata{Host: "internal.example", NetWork: C.UDP}
	prepared, err := ipStackDialMetadata(context.Background(), metadata, false)
	if err != nil || prepared.Host != metadata.Host {
		t.Fatalf("DIRECT preempted: %v %v", prepared, err)
	}
	if prepared.DstIP.IsValid() {
		t.Fatal("helper resolved DIRECT before its adapter")
	}

}

func TestIPStackHostsNeverRandomlySelectForbiddenFamily(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	node := &resolver.HostValue{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}}
	for _, p := range []resolver.IPQueryPolicy{resolver.IPQueryIPv4Only, resolver.IPQueryIPv6Only, resolver.IPQueryPreferIPv4, resolver.IPQueryPreferIPv6} {
		resolver.SetIPQueryPolicy(p)
		for i := 0; i < 50; i++ {
			ip, err := ipStackHostAddress(node)
			if err != nil || ip.Is4() != (p == resolver.IPQueryIPv4Only || p == resolver.IPQueryPreferIPv4) {
				t.Fatalf("mode %v: %v %v", p, ip, err)
			}
		}
	}
}
