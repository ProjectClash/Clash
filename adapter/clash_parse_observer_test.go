package adapter

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

func TestParsedProxiesAreReportedOnlyWhileObserved(t *testing.T) {
	node := map[string]any{"name": "d", "type": "direct"}
	var seen []outbound.ProxyAdapter
	stop := ClashObserveParsedProxies(func(proxy outbound.ProxyAdapter) { seen = append(seen, proxy) })
	proxy, err := ParseProxy(node)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Name() != "d" || proxy.Name() != "d" {
		t.Fatalf("observed %d nodes", len(seen))
	}
	if _, err := ParseProxy(node); err != nil || len(seen) != 1 {
		t.Fatalf("a node was observed after stop: %d", len(seen))
	}
}

func TestParsedProxyObserversNest(t *testing.T) {
	node := map[string]any{"name": "d", "type": "direct"}
	var outer, inner int
	stopOuter := ClashObserveParsedProxies(func(outbound.ProxyAdapter) { outer++ })
	stopInner := ClashObserveParsedProxies(func(outbound.ProxyAdapter) { inner++ })
	_, _ = ParseProxy(node)
	stopInner()
	_, _ = ParseProxy(node)
	stopOuter()
	_, _ = ParseProxy(node)
	if inner != 1 || outer != 1 {
		t.Fatalf("inner %d, outer %d; want 1 and 1", inner, outer)
	}
}
