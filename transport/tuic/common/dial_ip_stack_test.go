package common

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/resolver"
	"net"
	"net/netip"
	"testing"
)

type stackPacketSpy struct {
	seen netip.AddrPort
	err  error
}

func (p *stackPacketSpy) ListenPacket(_ context.Context, _ string, _ string, peer netip.AddrPort) (net.PacketConn, error) {
	p.seen = peer
	return nil, p.err
}
func TestIPStackQUICPreservesProxyPeerAndNativeWrapperCapability(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	original := dialer.DefaultAddressTransform
	defer func() { dialer.DefaultAddressTransform = original }()
	resolver.SetIPQueryPolicy(resolver.IPQueryDualStack)
	for _, physical := range []bool{false, true} {
		calls := 0
		dialer.DefaultAddressTransform = func(_ string, ip netip.Addr) (netip.Addr, error) {
			calls++
			return netip.MustParseAddr("192.0.2.9"), nil
		}
		sentinel := errors.New("packet spy reached")
		spy := &stackPacketSpy{err: sentinel}
		_, _, err := DialQuic(context.Background(), "[2001:db8::1]:443", nil, spy, nil, nil, DialQuicOption{PhysicalPeer: physical})
		if !errors.Is(err, sentinel) {
			t.Fatalf("physical=%v callback not reached: %v", physical, err)
		}
		if physical {
			if calls != 1 || spy.seen.Addr() != netip.MustParseAddr("192.0.2.9") {
				t.Fatalf("native wrapper lost transform: %d %v", calls, spy.seen)
			}
		} else {
			if calls != 0 || spy.seen.Addr() != netip.MustParseAddr("2001:db8::1") {
				t.Fatalf("proxy-carried logical peer changed: %d %v", calls, spy.seen)
			}
		}
	}
}
