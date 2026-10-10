package dns

import "testing"

func TestNewResolverAcceptsANameserverWithADisableTypesParam(t *testing.T) {
	for _, params := range []map[string]string{
		{"disable-ipv6": "true"},
		{"disable-qtype-65": "true"},
		{"disable-ipv4": "true"},
	} {
		ns := NameServer{Net: "udp", Addr: "223.5.5.5:53", Params: params}
		rs := NewResolver(Config{
			Main:   []NameServer{ns},
			Policy: []Policy{{Domain: "policy.example.com", NameServers: []NameServer{ns}}},
		})
		if rs.Resolver == nil || len(rs.Resolver.main) != 1 {
			t.Fatalf("params %v: main = %v, want the one wrapped client", params, rs.Resolver)
		}
		if _, ok := rs.Resolver.main[0].(clientWithDisableTypes); !ok {
			t.Fatalf("params %v: main[0] is %T, want clientWithDisableTypes", params, rs.Resolver.main[0])
		}
	}
}
