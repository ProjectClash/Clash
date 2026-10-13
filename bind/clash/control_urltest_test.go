package clash

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestURLTestEntryPointReadsTheOutcome(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	proxy := adapter.NewProxy(outbound.NewDirect())
	if got := urlTestDelay(proxy, bad.URL); got != -1 {
		t.Fatalf("a 403 answer must be -1, got %d", got)
	}
	if got := urlTestDelay(proxy, good.URL); got <= 0 {
		t.Fatalf("a 204 answer must be a positive delay, got %d", got)
	}
}

type stubProxyProvider struct {
	name    string
	proxies []C.Proxy
}

func (p *stubProxyProvider) Name() string               { return p.name }
func (p *stubProxyProvider) VehicleType() P.VehicleType { return P.File }
func (p *stubProxyProvider) Type() P.ProviderType       { return P.Proxy }
func (p *stubProxyProvider) Initial() error             { return nil }
func (p *stubProxyProvider) Update() error              { return nil }
func (p *stubProxyProvider) Proxies() []C.Proxy         { return p.proxies }
func (p *stubProxyProvider) ProxyList() C.ProxyList     { return C.ProxySlice(p.proxies) }
func (p *stubProxyProvider) Count() int                 { return len(p.proxies) }
func (p *stubProxyProvider) Touch()                     {}
func (p *stubProxyProvider) HealthCheck()               {}
func (p *stubProxyProvider) Version() uint32            { return 1 }
func (p *stubProxyProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}
func (p *stubProxyProvider) HealthCheckURL() string { return "" }

func TestURLTestFindsANodeThatOnlyAProviderHas(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	member := adapter.NewProxy(outbound.NewDirect())
	restore := swapTunnelProxies(
		map[string]C.Proxy{},
		map[string]P.ProxyProvider{
			"subscription": &stubProxyProvider{name: "subscription", proxies: []C.Proxy{member}},
		},
	)
	defer restore()

	if got := URLTest(member.Name(), good.URL); got <= 0 {
		t.Fatalf("a provider's own node must be testable, got %d", got)
	}
	if got := URLTest("nobody", good.URL); got != -1 {
		t.Fatalf("a name nothing has is still -1, got %d", got)
	}
}

func TestURLTestRefusesANameTwoProvidersBothClaim(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	shared := adapter.NewProxy(outbound.NewDirect())
	restore := swapTunnelProxies(
		map[string]C.Proxy{},
		map[string]P.ProxyProvider{
			"first":  &stubProxyProvider{name: "first", proxies: []C.Proxy{shared}},
			"second": &stubProxyProvider{name: "second", proxies: []C.Proxy{shared}},
		},
	)
	defer restore()

	if got := URLTest(shared.Name(), good.URL); got != -1 {
		t.Fatalf("an ambiguous name must not be guessed at, got %d", got)
	}
}

func TestURLTestPrefersTheGlobalTableOverAProvider(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	direct := adapter.NewProxy(outbound.NewDirect())
	shadow := adapter.NewProxy(outbound.NewRejectWithOption(
		outbound.RejectOption{Name: direct.Name()},
	))
	restore := swapTunnelProxies(
		map[string]C.Proxy{direct.Name(): direct},
		map[string]P.ProxyProvider{
			"subscription": &stubProxyProvider{name: "subscription", proxies: []C.Proxy{shadow}},
		},
	)
	defer restore()

	if got := URLTest(direct.Name(), good.URL); got <= 0 {
		t.Fatalf("the global table's entry must answer, got %d", got)
	}
}

func swapTunnelProxies(
	proxies map[string]C.Proxy,
	providers map[string]P.ProxyProvider,
) func() {
	previousProxies := tunnel.Proxies()
	previousProviders := tunnel.Providers()
	tunnel.UpdateProxies(proxies, providers)
	return func() { tunnel.UpdateProxies(previousProxies, previousProviders) }
}
