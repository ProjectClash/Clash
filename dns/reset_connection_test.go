package dns

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/component/trie"

	D "github.com/miekg/dns"
)


type resetCountingClient struct {
	resets atomic.Int64
}

func (c *resetCountingClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	return nil, context.Canceled
}

func (c *resetCountingClient) Address() string { return "counting" }

func (c *resetCountingClient) ResetConnection() { c.resets.Add(1) }

func TestResetConnectionReachesPolicyClients(t *testing.T) {
	mainClient := &resetCountingClient{}
	fallbackClient := &resetCountingClient{}
	triePolicyClient := &resetCountingClient{}
	matcherPolicyClient := &resetCountingClient{}
	defaultClient := &resetCountingClient{}

	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{triePolicyClient}); err != nil {
		t.Fatal(err)
	}

	resolver := &Resolver{
		main:     []dnsClient{mainClient},
		fallback: []dnsClient{fallbackClient},
		policy: []dnsPolicy{
			domainTriePolicy{DomainTrie: domainTrie},
			domainMatcherPolicy{dnsClients: []dnsClient{matcherPolicyClient}},
		},
		defaultResolver: &Resolver{main: []dnsClient{defaultClient}},
	}

	resolver.ResetConnection()

	for name, client := range map[string]*resetCountingClient{
		"main":             mainClient,
		"fallback":         fallbackClient,
		"defaultResolver":  defaultClient,
		"policy (trie)":    triePolicyClient,
		"policy (matcher)": matcherPolicyClient,
	} {
		if got := client.resets.Load(); got != 1 {
			t.Errorf("%s client was reset %d times, want 1", name, got)
		}
	}
}

func TestResetConnectionOnNilAndEmptyIsSafe(t *testing.T) {
	var nilResolver *Resolver
	nilResolver.ResetConnection()

	emptyTrie := trie.New[[]dnsClient]()
	(&Resolver{
		policy: []dnsPolicy{
			domainTriePolicy{DomainTrie: emptyTrie},
			domainMatcherPolicy{},
		},
	}).ResetConnection()
}

func TestClearCacheDoesNotPanicWithPolicies(t *testing.T) {
	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{&resetCountingClient{}}); err != nil {
		t.Fatal(err)
	}
	(&Resolver{
		policy: []dnsPolicy{domainTriePolicy{DomainTrie: domainTrie}},
	}).ClearCache()
}

func TestResetConnectionSurvivesADisableTypesPolicyClient(t *testing.T) {
	raw := &resetCountingClient{}
	wrapped := clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}

	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{wrapped}); err != nil {
		t.Fatal(err)
	}
	if err := domainTrie.Insert("+.wild.example.com", []dnsClient{wrapped}); err != nil {
		t.Fatal(err)
	}

	resolver := &Resolver{policy: []dnsPolicy{domainTriePolicy{DomainTrie: domainTrie}}}
	resolver.ResetConnection()

	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("raw transport behind the disable-types wrapper was reset %d times, want exactly 1", got)
	}
}

func TestResetConnectionResetsASharedRawTransportOnce(t *testing.T) {
	raw := &resetCountingClient{}
	asMain := clientWithEdns0Subnet{dnsClient: raw}
	asPolicy := clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeA: {}}}

	domainTrie := trie.New[[]dnsClient]()
	if err := domainTrie.Insert("policy.example.com", []dnsClient{asPolicy}); err != nil {
		t.Fatal(err)
	}

	resolver := &Resolver{
		main:     []dnsClient{asMain},
		fallback: []dnsClient{raw},
		policy: []dnsPolicy{
			domainTriePolicy{DomainTrie: domainTrie},
			domainMatcherPolicy{dnsClients: []dnsClient{asPolicy}},
		},
	}
	resolver.ResetConnection()

	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("shared raw transport was reset %d times across main/fallback/policy wrappers, want exactly 1", got)
	}
}

func TestAggregateResetConnectionResetsATransportSharedAcrossResolversOnce(t *testing.T) {
	raw := &resetCountingClient{}
	rs := Resolvers{
		Resolver:       &Resolver{main: []dnsClient{clientWithEdns0Subnet{dnsClient: raw}}},
		ProxyResolver:  &Resolver{main: []dnsClient{raw}},
		DirectResolver: &Resolver{main: []dnsClient{clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}}},
	}
	rs.ResetConnection()

	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("raw transport shared across main/proxy/direct resolvers was reset %d times, want exactly 1", got)
	}
}

func TestResolversContainsResolverNamesItsMembersOnly(t *testing.T) {
	main, proxy, direct, stranger := &Resolver{}, &Resolver{}, &Resolver{}, &Resolver{}
	rs := Resolvers{Resolver: main, ProxyResolver: proxy, DirectResolver: direct}
	for name, r := range map[string]*Resolver{"main": main, "proxy": proxy, "direct": direct} {
		if !rs.ContainsResolver(r) {
			t.Errorf("aggregate does not report its %s member as contained", name)
		}
	}
	if rs.ContainsResolver(stranger) {
		t.Error("aggregate reports a resolver it does not hold as contained")
	}
	if (Resolvers{}).ContainsResolver(main) {
		t.Error("an empty aggregate reports a member")
	}
}

func TestProductionResetConnectionResetsASharedTransportOnce(t *testing.T) {
	raw := &resetCountingClient{}
	rs := Resolvers{
		Resolver:       &Resolver{main: []dnsClient{clientWithEdns0Subnet{dnsClient: raw}}},
		ProxyResolver:  &Resolver{main: []dnsClient{raw}},
		DirectResolver: &Resolver{main: []dnsClient{clientWithDisableTypes{dnsClient: raw, disableTypes: map[uint16]struct{}{D.TypeAAAA: {}}}}},
	}

	priorDefault, priorProxy, priorDirect := resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver = priorDefault, priorProxy, priorDirect
	})
	resolver.DefaultResolver = rs
	resolver.ProxyServerHostResolver = rs.ProxyResolver
	resolver.DirectHostResolver = rs.DirectResolver

	resolver.ResetConnection()

	deadline := time.Now().Add(2 * time.Second)
	for raw.resets.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := raw.resets.Load(); got != 1 {
		t.Fatalf("through the production entry, a raw transport shared across main/proxy/direct was reset %d times, want exactly 1", got)
	}
}
