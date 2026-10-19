package dns

import (
	"context"
	"testing"

	"github.com/ProjectClash/Clash/component/netidentity"
	"github.com/ProjectClash/Clash/component/trie"
)

func TestASSIDPolicyStandsInForTheMainNameserversOnItsNetwork(t *testing.T) {
	t.Cleanup(netidentity.Reset)
	main, onHome, corp := &answeringClient{}, &answeringClient{}, &answeringClient{}
	tree := trie.New[[]dnsClient]()
	if err := tree.Insert("+.corp.internal", []dnsClient{corp}); err != nil {
		t.Fatal(err)
	}
	r := explainResolver(t, []dnsPolicy{domainTriePolicy{tree}, ssidPolicy{ssid: "Home", clients: []dnsClient{onHome}}}, []dnsClient{main})
	ask := func(name string) {
		t.Helper()
		r.ClearCache()
		if _, err := r.ExchangeContext(context.Background(), questionFor(name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, step := range []struct {
		ssid             string
		name             string
		main, home, corp int
	}{
		{"", "example.com.", 1, 0, 0},
		{"Home", "example.com.", 1, 1, 0},
		{"Home", "a.corp.internal.", 1, 1, 1},
		{"home", "example.com.", 2, 1, 1},
		{"Office", "example.com.", 3, 1, 1},
	} {
		netidentity.Set(netidentity.Identity{Kind: netidentity.KindWiFi, SSID: step.ssid})
		ask(step.name)
		if main.calls != step.main || onHome.calls != step.home || corp.calls != step.corp {
			t.Errorf("on %q asking %s: main %d, home %d, corp %d; want %d, %d, %d",
				step.ssid, step.name, main.calls, onHome.calls, corp.calls, step.main, step.home, step.corp)
		}
	}
}

func TestNewResolverTakesTheSSIDPoliciesAfterTheDomainOnes(t *testing.T) {
	ns := NameServer{Net: "udp", Addr: "127.0.0.1:53"}
	rs := NewResolver(Config{
		Main:       []NameServer{ns},
		Policy:     []Policy{{Domain: "corp.internal", NameServers: []NameServer{ns}}},
		SSIDPolicy: []SSIDPolicy{{SSID: "Home", NameServers: []NameServer{ns}}},
	})
	t.Cleanup(func() { NewResolver(Config{Main: []NameServer{ns}}) })
	if n := len(rs.Resolver.policy); n != 2 {
		t.Fatalf("%d policies, want the domain one and the SSID one", n)
	}
	if _, ok := rs.Resolver.policy[1].(ssidPolicy); !ok {
		t.Fatalf("the last policy is %T, want the SSID one", rs.Resolver.policy[1])
	}
	if !SSIDPoliciesInForce() {
		t.Fatal("a resolver with SSID policies is not reported")
	}
	NewResolver(Config{Main: []NameServer{ns}})
	if SSIDPoliciesInForce() {
		t.Fatal("a resolver without SSID policies is reported as having them")
	}
}
