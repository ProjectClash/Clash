package dns

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"

	D "github.com/miekg/dns"
)

type countingClient struct {
	name   string
	calls  atomic.Int32
	resets atomic.Int32
	fail   bool
}

func (c *countingClient) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	if c.fail {
		return nil, errors.New(c.name + " refused")
	}
	msg := new(D.Msg)
	msg.SetQuestion("example.com.", D.TypeA)
	msg.Response = true
	return msg, nil
}
func (c *countingClient) Address() string  { return c.name }
func (c *countingClient) ResetConnection() { c.resets.Add(1) }

func resetSubstituteState(t *testing.T) {
	t.Helper()
	MarkSystemSubstitutes(nil)
	SetSystemSubstitutesStale(false)
	t.Cleanup(func() {
		MarkSystemSubstitutes(nil)
		SetSystemSubstitutesStale(false)
	})
}

func TestSystemSubstituteAnswersFromItsChainOnlyWhileStale(t *testing.T) {
	resetSubstituteState(t)
	inner := &countingClient{name: "192.168.1.1:53"}
	other := &countingClient{name: "1.1.1.1:53"}
	wrapper := &systemSubstituteClient{dnsClient: inner}
	wrapper.setFallback([]dnsClient{other, wrapper})
	query := new(D.Msg)
	query.SetQuestion("example.com.", D.TypeA)
	if _, err := wrapper.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if inner.calls.Load() != 1 || other.calls.Load() != 0 {
		t.Fatalf("fresh substitute must answer itself: inner=%d other=%d", inner.calls.Load(), other.calls.Load())
	}
	if !SetSystemSubstitutesStale(true) {
		t.Fatal("the first stale mark must report a change")
	}
	if SetSystemSubstitutesStale(true) {
		t.Fatal("marking stale twice is not a change")
	}
	if _, err := wrapper.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if inner.calls.Load() != 1 || other.calls.Load() != 1 {
		t.Fatalf("stale substitute must answer from its chain: inner=%d other=%d", inner.calls.Load(), other.calls.Load())
	}
	if wrapper.Address() != "192.168.1.1:53[system-substitute stale]" {
		t.Fatalf("address = %q", wrapper.Address())
	}
	wrapper.ResetConnection()
	if inner.resets.Load() != 1 || other.resets.Load() != 1 {
		t.Fatalf("reset must reach the substitute and its chain: inner=%d other=%d", inner.resets.Load(), other.resets.Load())
	}
	if p := wrapper.fallback.Load(); p == nil || len(*p) != 1 {
		t.Fatalf("chain must not contain the wrapper itself: %v", p)
	}
	SetSystemSubstitutesStale(false)
	if _, err := wrapper.ExchangeContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if inner.calls.Load() != 2 {
		t.Fatalf("a restored substitute answers itself again: inner=%d", inner.calls.Load())
	}
}

func TestSystemSubstituteWithNoChainEndsAtUpstreamsPair(t *testing.T) {
	resetSubstituteState(t)
	wrapper := &systemSubstituteClient{dnsClient: &countingClient{name: "192.168.1.1:53", fail: true}}
	SetSystemSubstitutesStale(true)
	clients := wrapper.fallbackClients()
	if len(clients) != 2 || !strings.HasSuffix(clients[0].Address(), "114.114.114.114:53") || !strings.HasSuffix(clients[1].Address(), "8.8.8.8:53") {
		addrs := []string{}
		for _, c := range clients {
			addrs = append(addrs, c.Address())
		}
		t.Fatalf("empty chain must end at upstream's pair, got %v", addrs)
	}
	for _, c := range clients {
		if _, isWrapper := c.(*systemSubstituteClient); isWrapper {
			t.Fatal("upstream's pair must never be a substitute itself")
		}
	}
}

func TestResolverWiresSubstituteFallbacksBySlot(t *testing.T) {
	resetSubstituteState(t)
	MarkSystemSubstitutes([]string{"192.0.2.53", "192.0.2.54:53"})
	rs := NewResolver(Config{
		Main:         []NameServer{{Addr: "192.0.2.53:53"}, {Addr: "192.0.2.10:53"}},
		DirectServer: []NameServer{{Addr: "192.0.2.54:53"}},
		Default:      []NameServer{{Addr: "192.0.2.53:53"}},
	})
	mainWrappers := substituteWrappers(rs.Resolver.main)
	if len(mainWrappers) != 1 {
		t.Fatalf("main slot must hold one substitute wrapper, got %d (%v)", len(mainWrappers), rs.Resolver.main)
	}
	if p := mainWrappers[0].fallback.Load(); p == nil || len(*p) != 1 || !strings.HasSuffix((*p)[0].Address(), "192.0.2.10:53") {
		t.Fatalf("main substitute must fall back to the main slot's other resolver, got %v", p)
	}
	directWrappers := substituteWrappers(rs.DirectResolver.main)
	if len(directWrappers) != 1 {
		t.Fatalf("direct slot must hold one substitute wrapper, got %d", len(directWrappers))
	}
	if p := directWrappers[0].fallback.Load(); p == nil || len(*p) != 2 {
		t.Fatalf("direct substitute must fall back to the whole main slot, got %v", p)
	}
	if len(substituteWrappers(rs.Resolver.defaultResolver.main)) != 1 {
		t.Fatal("default-nameserver substitute must be wrapped too")
	}
	if p := substituteWrappers(rs.Resolver.defaultResolver.main)[0].fallback.Load(); p != nil {
		t.Fatal("a default-nameserver substitute keeps no chain: it ends at upstream's pair")
	}
	if isSystemSubstitute(NameServer{Addr: "192.0.2.53:53", Net: "tls"}) {
		t.Fatal("only plain udp/tcp entries can be substitutes")
	}
	if got := SystemSubstitutes(); len(got) != 2 || got[0] != "192.0.2.53:53" || got[1] != "192.0.2.54:53" {
		t.Fatalf("SystemSubstitutes = %v", got)
	}
}

func TestSeededLastResortGoesStaleWithTheSubstitutes(t *testing.T) {
	resetSubstituteState(t)
	MarkSystemSubstitutes([]string{"192.0.2.53"})
	SetSystemResolverDefaults([]string{"192.0.2.53"})
	t.Cleanup(func() { SetSystemResolverDefaults(nil) })
	system, ok := resolverSystemMainClient()
	if !ok {
		t.Fatal("resolver.SystemResolver must hold the system client")
	}
	if len(system.defaultNS) != 1 {
		t.Fatalf("seeded last resort = %v", system.defaultNS)
	}
	if _, isWrapper := system.defaultNS[0].(*systemSubstituteClient); !isWrapper {
		t.Fatalf("seeded last resort must be wrapped, got %T", system.defaultNS[0])
	}
	system.ResetConnection()
}

func resolverSystemMainClient() (*systemClient, bool) {
	rs, ok := resolver.SystemResolver.(Resolvers)
	if !ok || rs.Resolver == nil || len(rs.Resolver.main) != 1 {
		return nil, false
	}
	c, ok := rs.Resolver.main[0].(*systemClient)
	return c, ok
}
