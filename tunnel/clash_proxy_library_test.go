package tunnel

import (
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
)

type testLibrary []C.Proxy

func (l testLibrary) Len() int         { return len(l) }
func (l testLibrary) At(i int) C.Proxy { return l[i] }
func (l testLibrary) Lookup(name string) (C.Proxy, bool) {
	for _, node := range l {
		if node.Name() == name {
			return node, true
		}
	}
	return nil, false
}

func TestARuleReachesALibrarysNode(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	library := testLibrary{doorProxy{name: "node a", typ: C.Shadowsocks}, doorProxy{name: "node b", typ: C.Trojan}}
	match, err := R.ParseRule("MATCH", "", "node b", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateProxiesAndRules(waitTestProxies(), nil, []C.Rule{match}, nil, nil, library)
	SetMode(Rule)
	if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "node b" {
		t.Fatalf("matched %v (%v)", proxy, err)
	}
	if proxy, ok := LookupProxy("node a"); !ok || proxy.Name() != "node a" {
		t.Fatal("a library's node is not found by name")
	}
	if _, ok := Proxies()["node a"]; ok {
		t.Fatal("a library's node is in the proxy table")
	}
	seen := 0
	RangeProxies(func(string, C.Proxy) bool { seen++; return true })
	if seen != len(waitTestProxies())+len(library) {
		t.Fatalf("ranged over %d proxies", seen)
	}
	if _, ok := any(Tunnel).(interface{ LookupProxy(string) (C.Proxy, bool) }); !ok {
		t.Fatal("the tunnel does not look up a library's node for a dialer-proxy")
	}
	UpdateProxiesAndRules(waitTestProxies(), nil, []C.Rule{match}, nil, nil)
	if _, ok := LookupProxy("node a"); ok || ProxyLibrary() != nil {
		t.Fatal("a reload without a library kept the old one")
	}
}
