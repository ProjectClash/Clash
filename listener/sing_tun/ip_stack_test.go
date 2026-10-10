package sing_tun

import (
	"errors"
	"github.com/ProjectClash/Clash/component/resolver"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"net/netip"
	"testing"
	"time"
)

func TestIPStackDisallowedICMPDoesNotReturnFakeSuccess(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv4Only)
	h := &ListenerHandler{DisableICMPForwarding: true}
	_, err := h.PrepareConnection(N.NetworkICMP, M.Socksaddr{}, M.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1")}, nil, time.Second)
	if !errors.Is(err, resolver.ErrIPVersion) {
		t.Fatalf("forbidden ICMP accepted: %v", err)
	}
}
