package tunnel

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestResolutionRejectsClearedProxyTable(t *testing.T) {
	oldProxies, oldProviders, oldMode := loadProxies(), loadProviders(), Mode()
	oldRules, oldSubRules, oldRuleProviders := loadRules(), loadVersion().subRules, loadRuleProviders()
	t.Cleanup(func() {
		UpdateProxies(oldProxies, oldProviders)
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		SetMode(oldMode)
	})
	UpdateProxies(map[string]C.Proxy{}, nil)
	UpdateRules(nil, nil, nil)
	for _, m := range []TunnelMode{Direct, Global, Rule} {
		SetMode(m)
		metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
		p, _, err := resolveMetadataContext(context.Background(), metadata)
		if p != nil || err == nil {
			t.Errorf("mode %v returned proxy=%v err=%v after shutdown cleared the table", m, p, err)
		}
	}
	metadata := &C.Metadata{SpecialProxy: "gone"}
	UpdateProxies(map[string]C.Proxy{"gone": nil}, nil)
	if p, _, err := resolveMetadataContext(context.Background(), metadata); p != nil || err == nil {
		t.Fatalf("nil special proxy: %v %v", p, err)
	}
}

func TestProxyLookupDuringReplacement(t *testing.T) {
	oldProxies, oldProviders, oldMode := loadProxies(), loadProviders(), Mode()
	t.Cleanup(func() { UpdateProxies(oldProxies, oldProviders); SetMode(oldMode) })
	p := doorProxy{name: "DIRECT", typ: C.Direct}
	ready := map[string]C.Proxy{"DIRECT": p, "GLOBAL": p, "chosen": p}
	for _, m := range []TunnelMode{Direct, Global} {
		SetMode(m)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 500; n++ {
				UpdateProxies(ready, nil)
				UpdateProxies(map[string]C.Proxy{}, nil)
			}
		}()
		for n := 0; n < 500; n++ {
			for _, special := range []string{"", "chosen"} {
				metadata := &C.Metadata{SpecialProxy: special, NetWork: C.TCP, Type: C.INNER, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
				proxy, _, err := resolveMetadataContext(context.Background(), metadata)
				if proxy == nil && err == nil {
					t.Error("lookup returned nil success during replacement")
				}
			}
		}
		wg.Wait()
	}
}
