package tunnel

import (
	"context"
	"github.com/ProjectClash/Clash/component/resolver"
	R "github.com/ProjectClash/Clash/rules"
	"net/netip"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/inner"
)

type cancelDialProxy struct {
	C.Proxy
	entered chan context.Context
}

func (*cancelDialProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (*cancelDialProxy) Name() string                     { return "cancel-dial" }
func (*cancelDialProxy) Type() C.AdapterType              { return C.Socks5 }
func (*cancelDialProxy) IsL3Protocol(*C.Metadata) bool    { return false }
func (p *cancelDialProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.entered <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestInternalConnectionCloseCancelsRealTunnelDial(t *testing.T) {
	oldProxies, oldProviders, oldStatus := loadProxies(), loadProviders(), status.Load()
	oldInner := inner.GetTunnel()
	defer func() {
		inner.CloseTCPConnections()
		inner.New(oldInner)
		UpdateProxies(oldProxies, oldProviders)
		status.Store(oldStatus)
	}()
	p := &cancelDialProxy{entered: make(chan context.Context, 10)}
	UpdateProxies(map[string]C.Proxy{p.Name(): p}, nil)
	OnInnerLoading()
	inner.New(Tunnel)
	conn, err := inner.HandleTcp(Tunnel, "192.0.2.1:443", p.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var dialCtx context.Context
	select {
	case dialCtx = <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("internal handler did not reach outbound dial")
	}
	conn.Close()
	select {
	case <-dialCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("internal connection close did not cancel actual tunnel dial")
	}
	inner.CloseTCPConnections()
}

type cancelRuleResolver struct {
	resolver.Resolver
	entered chan context.Context
}

func (*cancelRuleResolver) Invalid() bool { return true }
func (r *cancelRuleResolver) LookupIPv4(ctx context.Context, _ string) ([]netip.Addr, error) {
	r.entered <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRuleResolutionInheritsInternalContext(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	ipRule, err := R.ParseRule("IP-CIDR", "192.0.2.0/24", "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateRules(append([]C.Rule{ipRule}, Rules()...), nil, nil)
	oldResolver, oldIPv6, oldPolicy := resolver.DefaultResolver, resolver.DisableIPv6, resolver.CurrentIPQueryPolicy()
	defer func() {
		resolver.DefaultResolver = oldResolver
		resolver.DisableIPv6 = oldIPv6
		resolver.SetIPQueryPolicy(oldPolicy)
	}()
	r := &cancelRuleResolver{entered: make(chan context.Context, 1)}
	resolver.DefaultResolver = r
	resolver.DisableIPv6 = true
	resolver.SetIPQueryPolicy(resolver.IPQueryLegacy)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		_, _, _ = resolveMetadataContext(ctx, &C.Metadata{Type: C.INNER, NetWork: C.TCP, Host: "cancel-rule.invalid", DstPort: 443})
	}()
	var queryCtx context.Context
	select {
	case queryCtx = <-r.entered:
	case <-time.After(time.Second):
		t.Fatal("rule match did not enter DNS resolution")
	}
	cancel()
	select {
	case <-queryCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("rule DNS did not inherit internal request cancellation")
	}
}
