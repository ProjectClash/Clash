package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestTheChosenNodesAreWhatTheGroupsHaveChosen(t *testing.T) {
	a := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "a"}))
	b := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "b"}))
	members, err := provider.NewCompatibleProvider("members", []C.Proxy{a, b}, provider.NewHealthCheck([]C.Proxy{a, b}, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	selector, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: "pick"}, outboundgroup.SelectorOption{}, a, []P.ProxyProvider{members})
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.Set("b"); err != nil {
		t.Fatal(err)
	}
	restore := swapTunnelProxies(map[string]C.Proxy{"a": a, "b": b, "pick": adapter.NewProxy(selector)}, map[string]P.ProxyProvider{})
	defer restore()

	chosen := chosenNodeNames()
	if _, ok := chosen["b"]; !ok || len(chosen) != 1 {
		t.Fatalf("chosen %v, want only b", chosen)
	}
}
