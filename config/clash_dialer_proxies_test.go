package config

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

func dialerTestProxies(t *testing.T, chains map[string]string) map[string]C.Proxy {
	t.Helper()
	proxies := make(map[string]C.Proxy, len(chains))
	for name, via := range chains {
		node, err := outbound.NewSocks5(outbound.Socks5Option{BasicOption: outbound.BasicOption{DialerProxy: via}, Name: name, Server: "127.0.0.1", Port: 1080})
		if err != nil {
			t.Fatal(err)
		}
		proxies[name] = adapter.NewProxy(node)
	}
	return proxies
}

func TestDialerProxiesAnswerAsUpstream(t *testing.T) {
	if err := validateDialerProxies(dialerTestProxies(t, map[string]string{"a": "b", "b": "c", "c": "", "d": "c"})); err != nil {
		t.Fatal(err)
	}
	err := validateDialerProxies(dialerTestProxies(t, map[string]string{"a": "missing"}))
	if err == nil || err.Error() != "proxy [a] dialer-proxy [missing] not found" {
		t.Fatalf("%v", err)
	}
	for i := 0; i < 20; i++ {
		err = validateDialerProxies(dialerTestProxies(t, map[string]string{"x": "a", "a": "b", "b": "c", "c": "a", "free": ""}))
		if err == nil || !strings.HasSuffix(err.Error(), "] has circular dialer-proxy dependency") ||
			strings.Contains(err.Error(), "[free]") {
			t.Fatalf("%v", err)
		}
	}
	if err := validateDialerProxies(dialerTestProxies(t, map[string]string{"self": "self"})); err == nil {
		t.Fatal("a node that dials through itself passed")
	}
}

func TestDialerProxiesCostInProportionToTheNodes(t *testing.T) {
	chains := map[string]string{"hub": ""}
	for i := 0; i < 20000; i++ {
		chains[fmt.Sprintf("n%d", i)] = "hub"
	}
	proxies := dialerTestProxies(t, chains)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := validateDialerProxies(proxies); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Fatalf("checking 20k chained nodes allocated %d MiB", allocated>>20)
	}
}
