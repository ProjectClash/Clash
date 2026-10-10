package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/dns"

	D "github.com/miekg/dns"
)

func installResolver(t *testing.T, config dns.Config) {
	t.Helper()
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = dns.NewResolver(config)
}

func nameservers(addresses ...string) []dns.NameServer {
	servers := make([]dns.NameServer, 0, len(addresses))
	for _, address := range addresses {
		servers = append(servers, dns.NameServer{Addr: address})
	}
	return servers
}

func explainOK(t *testing.T, target string) map[string]any {
	t.Helper()
	body, status := decodeExplain(t, target)
	if status != 200 {
		t.Fatalf("GET %s: status %d, body %v", target, status, body)
	}
	return body
}

func candidateList(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["candidates"].([]any)
	list := make([]string, 0, len(raw))
	for _, item := range raw {
		text, _ := item.(string)
		list = append(list, text)
	}
	return list
}

func TestExplainLiveReportsMainNameserversInOrder(t *testing.T) {
	installResolver(t, dns.Config{Main: nameservers("223.5.5.5:53", "119.29.29.29:53")})

	body := explainOK(t, "/clash/v1/dns/explain?domain=example.com")
	if body["source"] != "main" {
		t.Fatalf("a name no policy claims was not attributed to main: %v", body["source"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 2 {
		t.Fatalf("two configured nameservers produced %d candidates: %v", len(candidates), candidates)
	}
	if !strings.Contains(candidates[0], "223.5.5.5") || !strings.Contains(candidates[1], "119.29.29.29") {
		t.Fatalf("candidates are not in configuration order: %v", candidates)
	}
}

func TestExplainLiveReportsAnExactPolicyKey(t *testing.T) {
	installResolver(t, dns.Config{
		Main: nameservers("223.5.5.5:53"),
		Policy: []dns.Policy{
			{Domain: "example.com", NameServers: nameservers("1.1.1.1:53")},
		},
	})

	body := explainOK(t, "/clash/v1/dns/explain?domain=example.com")
	if body["source"] != "policy" {
		t.Fatalf("a name claimed by nameserver-policy was attributed to %v", body["source"])
	}
	if body["matchedRule"] != "example.com" {
		t.Fatalf("matched rule reported as %v, not the key the config wrote", body["matchedRule"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 1 || !strings.Contains(candidates[0], "1.1.1.1") {
		t.Fatalf("policy candidates are the main nameservers, not the policy's: %v", candidates)
	}
}

func TestExplainLiveReportsAWildcardPolicyKey(t *testing.T) {
	installResolver(t, dns.Config{
		Main: nameservers("223.5.5.5:53"),
		Policy: []dns.Policy{
			{Domain: "+.example.com", NameServers: nameservers("1.1.1.1:53")},
		},
	})

	body := explainOK(t, "/clash/v1/dns/explain?domain=api.example.com")
	if body["source"] != "policy" {
		t.Fatalf("a subdomain under a wildcard policy was attributed to %v", body["source"])
	}
	rule, _ := body["matchedRule"].(string)
	if !strings.Contains(rule, "example.com") {
		t.Fatalf("wildcard policy reported as %q, which does not name the key", rule)
	}
}

func TestExplainLiveDoesNotClaimNamesOutsideThePolicy(t *testing.T) {
	installResolver(t, dns.Config{
		Main: nameservers("223.5.5.5:53"),
		Policy: []dns.Policy{
			{Domain: "+.example.com", NameServers: nameservers("1.1.1.1:53")},
		},
	})

	body := explainOK(t, "/clash/v1/dns/explain?domain=example.org")
	if body["source"] != "main" {
		t.Fatalf("an unrelated name was claimed by the policy: %v", body)
	}
	if body["matchedRule"] != nil && body["matchedRule"] != "" {
		t.Fatalf("an unrelated name reported a matched rule: %v", body["matchedRule"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 1 || !strings.Contains(candidates[0], "223.5.5.5") {
		t.Fatalf("an unrelated name did not fall through to main: %v", candidates)
	}
}

func TestExplainLiveSendsNothingByDefault(t *testing.T) {
	installResolver(t, dns.Config{Main: nameservers("203.0.113.1:53")})

	body := explainOK(t, "/clash/v1/dns/explain?domain=example.com")
	if body["probed"] != false {
		t.Fatalf("probed reported as %v without probe=1", body["probed"])
	}
	if body["answeredBy"] != nil && body["answeredBy"] != "" {
		t.Fatalf("named a winner without sending a query: %v", body["answeredBy"])
	}
	if body["answer"] != nil {
		t.Fatalf("returned an answer without sending a query: %v", body["answer"])
	}
}

func TestExplainLiveAcceptsEveryTypeTheOtherEndpointDoes(t *testing.T) {
	installResolver(t, dns.Config{Main: nameservers("223.5.5.5:53")})

	for _, queryType := range []string{"A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "PTR"} {
		if _, known := D.StringToType[queryType]; !known {
			t.Fatalf("%s is not a type upstream knows, so this test is asserting fiction", queryType)
		}
		body, status := decodeExplain(t, "/clash/v1/dns/explain?domain=example.com&type="+queryType)
		if status != 200 {
			t.Fatalf("asked to explain %s and got %d: %v — the route section vanishes for "+
				"this type while /dns/query answers it", queryType, status, body)
		}
		if body["type"] != queryType {
			t.Fatalf("asked for %s and was told %v", queryType, body["type"])
		}
		source, _ := body["source"].(string)
		if source == "" {
			t.Fatalf("%s was accepted but explained nothing: %v", queryType, body)
		}
		if source == "main" || source == "policy" || source == "fallback" {
			if len(candidateList(t, body)) == 0 {
				t.Fatalf("%s was attributed to %s and named no resolver: %v", queryType, source, body)
			}
		}
	}
	if body := explainOK(t, "/clash/v1/dns/explain?domain=example.com"); body["type"] != "A" {
		t.Fatalf("an omitted type produced %v", body["type"])
	}
	if _, status := decodeExplain(t, "/clash/v1/dns/explain?domain=example.com&type=NOTATYPE"); status == 200 {
		t.Fatal("accepted a query type that does not exist")
	}
}

type explainDomainFilter struct{ suffix string }

func (f explainDomainFilter) MatchDomain(domain string) bool {
	return domain == f.suffix || strings.HasSuffix(domain, "."+f.suffix)
}

func TestExplainLiveReportsTheFallbackBranch(t *testing.T) {
	installResolver(t, dns.Config{
		Main:                 nameservers("223.5.5.5:53"),
		Fallback:             nameservers("1.1.1.1:53"),
		FallbackDomainFilter: []C.DomainMatcher{explainDomainFilter{suffix: "example.com"}},
	})

	body := explainOK(t, "/clash/v1/dns/explain?domain=api.example.com")
	if body["source"] != "fallback" {
		t.Fatalf("a name the fallback filter claims was attributed to %v", body["source"])
	}
	candidates := candidateList(t, body)
	if len(candidates) != 1 || !strings.Contains(candidates[0], "1.1.1.1") {
		t.Fatalf("fallback candidates are not the fallback nameservers: %v", candidates)
	}

	other := explainOK(t, "/clash/v1/dns/explain?domain=example.org")
	if other["source"] != "main" {
		t.Fatalf("a name outside the fallback filter was attributed to %v", other["source"])
	}
}

func TestExplainableResolverAcceptsEveryShapeThatCanBeInstalled(t *testing.T) {
	installed := dns.NewResolver(dns.Config{Main: nameservers("223.5.5.5:53")})
	if explainableResolver(installed) == nil {
		t.Fatal("rejected the dns.Resolvers value hub/executor installs")
	}
	if explainableResolver(&installed) == nil {
		t.Fatal("rejected a *dns.Resolvers")
	}
	if explainableResolver(installed.Resolver) == nil {
		t.Fatal("rejected the bare *dns.Resolver NewResolverFromClient returns")
	}
	if explainableResolver(nil) != nil {
		t.Fatal("accepted nil")
	}
	if explainableResolver((*dns.Resolvers)(nil)) != nil {
		t.Fatal("accepted a typed-nil *dns.Resolvers, which would panic on use")
	}
	if explainableResolver("not a resolver") != nil {
		t.Fatal("accepted a value that is not a resolver at all")
	}
}
