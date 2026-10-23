//go:build no_easytier

package outboundgroup

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestAGroupExcludesTheEasyTierPlaceholderByItsDeclaredType(t *testing.T) {
	placeholder, err := outbound.NewEasyTier(outbound.EasyTierOption{Name: "mesh"})
	if err != nil {
		t.Fatal(err)
	}
	members := []C.Proxy{
		adapter.NewProxy(placeholder),
		adapter.NewProxy(outbound.NewRejectWithOption(outbound.RejectOption{Name: "block"})),
		adapter.NewProxy(outbound.NewDirect()),
	}
	for excludeType, want := range map[string][]string{
		"EasyTier":       {"block", "DIRECT"},
		"easytier":       {"block", "DIRECT"},
		"Reject":         {"DIRECT"},
		"Vmess|EasyTier": {"block", "DIRECT"},
		"Direct":         {"mesh", "block"},
	} {
		compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
		if err != nil {
			t.Fatal(err)
		}
		group := NewGroupBase(GroupBaseOption{Name: "g", Type: C.Selector, ExcludeType: excludeType, Providers: []P.ProxyProvider{compatible}})
		var got []string
		for _, proxy := range group.GetProxies(false) {
			got = append(got, proxy.Name())
		}
		if len(got) != len(want) {
			t.Errorf("exclude-type %q: %v, want %v", excludeType, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("exclude-type %q: %v, want %v", excludeType, got, want)
				break
			}
		}
	}
}
