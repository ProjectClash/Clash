package outboundgroup

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestASelectionIsReadWhileItIsSet(t *testing.T) {
	var members []C.Proxy
	for i := 0; i < 3; i++ {
		members = append(members, adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("N %d", i)})))
	}
	empty := adapter.NewProxy(outbound.NewCompatible())
	compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	providers := []P.ProxyProvider{compatible}
	common := GroupCommonOption{Name: "g", URL: "https://example.net/"}
	selector, err := NewSelector(common, SelectorOption{DefaultSelected: "N 1"}, empty, providers)
	if err != nil {
		t.Fatal(err)
	}
	if now, _, _, _ := ClashSelection(selector); now != "N 1" {
		t.Fatalf("the default selection: %q", now)
	}
	urlTest, err := NewURLTest(common, URLTestOption{}, empty, providers)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := NewFallback(common, FallbackOption{}, empty, providers)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []interface {
		ProxyGroup
		ForceSet(string)
		ClashAppendJSON([]byte) []byte
	}{selector, urlTest, fallback} {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				group.ForceSet(fmt.Sprintf("N %d", i%3))
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ClashSelection(group)
				group.ClashAppendJSON(nil)
				_ = group.Now()
			}
		}()
		wg.Wait()
		group.ForceSet("N 2")
		if _, _, fixed, hasFixed := ClashSelection(group); hasFixed && fixed != "N 2" {
			t.Fatalf("%T: fixed %q after ForceSet", group, fixed)
		}
	}
}

func TestAFallbackPastADeadPinTakesTheNextAliveMember(t *testing.T) {
	const testURL = "http://127.0.0.1:1/"
	var members []C.Proxy
	for _, name := range []string{"dead first", "dead pin", "alive next"} {
		members = append(members, adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name})))
	}
	adapter.SetURLTestAdmission(nil)
	for _, dead := range members[:2] {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = dead.URLTest(ctx, testURL, nil)
		cancel()
		if dead.AliveForTestUrl(testURL) {
			t.Fatalf("%s measured alive at a closed port", dead.Name())
		}
	}
	compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := NewFallback(GroupCommonOption{Name: "f", URL: testURL}, FallbackOption{}, adapter.NewProxy(outbound.NewCompatible()), []P.ProxyProvider{compatible})
	if err != nil {
		t.Fatal(err)
	}
	fallback.ForceSet("dead pin")
	if now := fallback.Now(); now != "alive next" {
		t.Fatalf("past a dead pin: %q, want the next alive member", now)
	}
	if _, _, fixed, _ := ClashSelection(fallback); fixed != "" {
		t.Fatalf("a dead pin stays pinned: %q", fixed)
	}
}

type changingProvider struct {
	*provider.CompatibleProvider
	mu      sync.Mutex
	nodes   C.ProxySlice
	version uint32
}

func (p *changingProvider) ProxyList() C.ProxyList {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.nodes
}
func (p *changingProvider) Proxies() []C.Proxy { return C.ProxiesOf(p.ProxyList()) }
func (p *changingProvider) Version() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}
func (p *changingProvider) VehicleType() P.VehicleType { return P.HTTP }
func (p *changingProvider) set(nodes ...C.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes, p.version = nodes, p.version+1
}

func TestASelectorWhoseFilterNowMatchesNothingUsesItsFallback(t *testing.T) {
	node := func(name string) C.Proxy {
		return adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name}))
	}
	base, err := provider.NewCompatibleProvider("sub", []C.Proxy{node("seed")}, provider.NewHealthCheck(nil, "", 5000, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	sub := &changingProvider{CompatibleProvider: base}
	sub.set(node("US-A"), node("JP-B"))
	fallback := adapter.NewProxy(outbound.NewReject())
	selector, err := NewSelector(GroupCommonOption{Name: "g", Filter: "US"}, SelectorOption{}, fallback, []P.ProxyProvider{sub})
	if err != nil {
		t.Fatal(err)
	}
	selector.ForceSet("US-A")
	if got := selector.Unwrap(nil, true).Name(); got != "US-A" {
		t.Fatalf("selected %q", got)
	}
	sub.set(node("JP-B"))
	if got := selector.Unwrap(nil, true); got != fallback {
		t.Fatalf("with no member left the selector routes through %q", got.Name())
	}
	sub.set(node("US-A"), node("JP-B"))
	if got := selector.Unwrap(nil, true).Name(); got != "US-A" {
		t.Fatalf("the member came back but the selector routes through %q", got)
	}
}
