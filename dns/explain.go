package dns

import (
	"context"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"

	D "github.com/miekg/dns"
)

type Explanation struct {
	Source string
	MatchedRule string
	Candidates []string
	AnsweredBy string
	Answer     *D.Msg
	CacheExpiresAt *time.Time
	CacheStale     bool
}

const (
	ExplainSourceCache    = "cache"
	ExplainSourceRcode    = "rcode"
	ExplainSourcePolicy   = "policy"
	ExplainSourceFallback = "fallback"
	ExplainSourceMain     = "main"
	ExplainSourceHosts  = "hosts"
	ExplainSourceFakeIP = "fake-ip"
	ExplainSourceIPv6Disabled = "ipv6-disabled"
	ExplainSourceIPStack      = "ip-stack"
)

type middlewareAware interface {
	UseHosts() bool
	ShouldSkipFakeIP(string) bool
	IPv6() bool
}

var _ middlewareAware = (*ResolverEnhancer)(nil)

func shortCircuitedAboveTheResolver(m *D.Msg) string {
	if len(m.Question) == 0 {
		return ""
	}
	q := m.Question[0]
	if !resolver.CurrentIPQueryPolicy().AllowsQueryType(q.Qtype) {
		return ExplainSourceIPStack
	}
	host := strings.TrimRight(q.Name, ".")

	aware, _ := resolver.DefaultHostMapper.(middlewareAware)

	if aware != nil && aware.UseHosts() && isIPRequest(q) {
		if _, ok := resolver.DefaultHosts.Search(host, q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA); ok {
			return ExplainSourceHosts
		}
	}

	if resolver.FakeIPEnabled() {
		switch q.Qtype {
		case D.TypeSVCB, D.TypeHTTPS:
			if aware == nil || !aware.ShouldSkipFakeIP(host) {
				return ExplainSourceFakeIP
			}
		case D.TypeA, D.TypeAAAA:
			if aware == nil || !aware.ShouldSkipFakeIP(host) {
				return ExplainSourceFakeIP
			}
		}
	}

	if q.Qtype == D.TypeAAAA && aware != nil && !aware.IPv6() {
		return ExplainSourceIPv6Disabled
	}
	return ""
}

func (r *Resolver) Explain(ctx context.Context, m *D.Msg, probe bool) Explanation {
	explanation := Explanation{Source: ExplainSourceMain}
	if r == nil || m == nil || len(m.Question) == 0 {
		return explanation
	}

	if source := shortCircuitedAboveTheResolver(m); source != "" {
		explanation.Source = source
		return explanation
	}

	if msg, expireAt, hit := getMsgFromCache(r.cache, m.Question[0]); hit && msg != nil {
		at := expireAt
		explanation.Source = ExplainSourceCache
		explanation.CacheExpiresAt = &at
		explanation.CacheStale = !expireAt.After(time.Now())
	}

	clients := r.resolveCandidates(m, &explanation)
	for _, client := range clients {
		explanation.Candidates = append(explanation.Candidates, client.Address())
	}

	if !probe || len(clients) == 0 {
		return explanation
	}

	answer, answeredBy := probeExchange(ctx, clients, m)
	explanation.Answer, explanation.AnsweredBy = answer, answeredBy
	return explanation
}

func (r *Resolver) resolveCandidates(m *D.Msg, explanation *Explanation) []dnsClient {
	if clients := r.matchPolicy(m); len(clients) > 0 {
		if explanation.Source != ExplainSourceCache {
			explanation.Source = ExplainSourcePolicy
		}
		explanation.MatchedRule = r.describeMatchedPolicy(m)
		return r.markRcode(clients, explanation)
	}
	if r.shouldOnlyQueryFallback(m) {
		if explanation.Source != ExplainSourceCache {
			explanation.Source = ExplainSourceFallback
		}
		return r.markRcode(r.fallback, explanation)
	}
	return r.markRcode(r.main, explanation)
}

func (r *Resolver) markRcode(clients []dnsClient, explanation *Explanation) []dnsClient {
	for _, client := range clients {
		if _, isRCode := client.(rcodeClient); isRCode {
			if explanation.Source != ExplainSourceCache {
				explanation.Source = ExplainSourceRcode
			}
			return clients
		}
	}
	return clients
}

func (r *Resolver) describeMatchedPolicy(m *D.Msg) string {
	domain := msgToDomain(m)
	if domain == "" {
		return ""
	}
	for _, policy := range r.policy {
		matched := policy.Match(domain)
		if len(matched) == 0 {
			continue
		}
		switch actual := policy.(type) {
		case domainTriePolicy:
			return describeTrieKeys(actual, matched)
		case domainMatcherPolicy:
			if named, ok := actual.matcher.(interface{ Name() string }); ok {
				return named.Name()
			}
			return ""
		}
		return ""
	}
	return ""
}

func describeTrieKeys(policy domainTriePolicy, matched []dnsClient) string {
	if policy.DomainTrie == nil {
		return ""
	}
	var keys []string
	policy.DomainTrie.Foreach(func(domain string, data []dnsClient) bool {
		if sameClients(data, matched) {
			keys = append(keys, domain)
		}
		return true
	})
	return strings.Join(keys, ", ")
}

func sameClients(a, b []dnsClient) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func probeExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (*D.Msg, string) {
	for _, client := range clients {
		if _, isRCode := client.(rcodeClient); isRCode {
			answer, err := client.ExchangeContext(ctx, m)
			if err != nil {
				return nil, ""
			}
			return answer, client.Address()
		}
	}
	if len(clients) == 1 {
		answer, err := clients[0].ExchangeContext(ctx, m)
		if err != nil {
			return nil, ""
		}
		return answer, clients[0].Address()
	}
	answer, _, err := batchExchange(ctx, clients, m)
	if err != nil {
		return nil, ""
	}
	return answer, ""
}
