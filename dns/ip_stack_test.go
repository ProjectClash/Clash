package dns

import (
	"context"
	"github.com/ProjectClash/Clash/component/fakeip"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	icontext "github.com/ProjectClash/Clash/context"
	D "github.com/miekg/dns"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestIPStackFiltersBeforeHostsAndFakeAnswers(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	for _, tc := range []struct {
		p       resolver.IPQueryPolicy
		blocked uint16
		allowed uint16
	}{{resolver.IPQueryIPv4Only, D.TypeAAAA, D.TypeA}, {resolver.IPQueryIPv6Only, D.TypeA, D.TypeAAAA}} {
		resolver.SetIPQueryPolicy(tc.p)
		calls := 0
		h := withIPQueryPolicy(func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) { calls++; return r, nil })
		for _, q := range []uint16{tc.blocked, tc.allowed, D.TypeTXT} {
			msg := new(D.Msg)
			msg.SetQuestion("stack.example.", q)
			result, err := h(nil, msg)
			if err != nil {
				t.Fatal(err)
			}
			if q == tc.blocked && (len(result.Answer) != 0 || calls != 0) {
				t.Fatal("blocked request reached DNS middleware")
			}
		}
		if calls != 2 {
			t.Fatalf("allowed query lost: %d", calls)
		}
	}
}

func TestFakeIPWithoutIPv6PoolAnswersAAAAEmptyInEveryQueryMode(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	for _, p := range []resolver.IPQueryPolicy{resolver.IPQueryLegacy, resolver.IPQueryDualStack, resolver.IPQueryPreferIPv4, resolver.IPQueryPreferIPv6, resolver.IPQueryIPv6Only} {
		resolver.SetIPQueryPolicy(p)
		called := false
		h := withFakeIP(&fakeip.Skipper{}, nil, nil, 60)(func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) { called = true; return r, nil })
		msg := new(D.Msg)
		msg.SetQuestion("stack.example.", D.TypeAAAA)
		answer, err := h(nil, msg)
		if err != nil {
			t.Fatal(err)
		}
		if called {
			t.Fatalf("mode %v: AAAA without a v6 fake pool must never reach the real resolver", p)
		}
		if answer == nil || answer.Rcode != D.RcodeSuccess || len(answer.Answer) != 0 {
			t.Fatalf("mode %v: the answer is an authoritative empty one, got %v", p, answer)
		}
	}
}

type stackAAAAClient struct{ calls atomic.Int32 }

func (c *stackAAAAClient) ExchangeContext(_ context.Context, m *D.Msg) (*D.Msg, error) {
	c.calls.Add(1)
	reply := new(D.Msg)
	reply.SetReply(m)
	reply.Answer = []D.RR{&D.AAAA{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 60}, AAAA: netip.MustParseAddr("2001:db8::9").AsSlice()}}
	return reply, nil
}
func (c *stackAAAAClient) Address() string  { return "stack-answer" }
func (c *stackAAAAClient) ResetConnection() {}
func TestFakeIPWithoutIPv6PoolHandlerAndExplainAgreeOnEmptyAAAA(t *testing.T) {
	old := resolver.CurrentIPQueryPolicy()
	defer resolver.SetIPQueryPolicy(old)
	oldMapper := resolver.DefaultHostMapper
	defer func() { resolver.DefaultHostMapper = oldMapper }()
	resolver.SetIPQueryPolicy(resolver.IPQueryIPv6Only)
	mapper := NewEnhancer(EnhancerConfig{IPv6: true, EnhancedMode: C.DNSFakeIP, FakeIPSkipper: &fakeip.Skipper{}})
	resolver.DefaultHostMapper = mapper
	client := &stackAAAAClient{}
	r := explainResolver(t, nil, []dnsClient{client})
	r.ipv6 = true
	defer r.CloseQueries()
	q := new(D.Msg)
	q.SetQuestion("stack-real.example.", D.TypeAAAA)
	explanation := r.Explain(context.Background(), q, true)
	if explanation.Source != ExplainSourceFakeIP || client.calls.Load() != 0 {
		t.Fatalf("Explain must say the fake-ip layer answers this AAAA (empty), and no upstream is asked: %#v calls=%d", explanation, client.calls.Load())
	}
	answer, err := newHandler(r, mapper)(icontext.NewDNSContext(context.Background()), q)
	if err != nil || len(answer.Answer) != 0 || client.calls.Load() != 0 {
		t.Fatalf("the handler answers AAAA empty without a v6 pool: %v %v calls=%d", answer, err, client.calls.Load())
	}
	before := client.calls.Load()
	q.SetQuestion("blocked.example.", D.TypeA)
	resolver.DefaultHostMapper = NewEnhancer(EnhancerConfig{IPv6: true, EnhancedMode: C.DNSNormal})
	explanation = r.Explain(context.Background(), q, true)
	if explanation.Source != ExplainSourceIPStack {
		t.Fatalf("source=%q", explanation.Source)
	}
	if client.calls.Load() != before || len(explanation.Candidates) != 0 || explanation.Answer != nil {
		t.Fatal("diagnostic probe bypassed only-AAAA restriction")
	}
}
