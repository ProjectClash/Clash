package route

import (
	"fmt"
	"testing"

	"github.com/metacubex/http/httptest"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"

	"github.com/metacubex/chi/render"
)

func TestGetProxiesWritesRenderJSONsBytes(t *testing.T) {
	proxies := map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}
	for i := 0; i < 20; i++ {
		proxy, err := adapter.ParseProxy(map[string]any{
			"name": fmt.Sprintf("node <%d> & co", i), "type": "ss", "server": "127.0.0.1", "port": 9,
			"cipher": "aes-128-gcm", "password": "p",
		})
		if err != nil {
			t.Fatal(err)
		}
		proxies[proxy.Name()] = proxy
	}
	request := httptest.NewRequest("GET", "/proxies", nil)
	want := httptest.NewRecorder()
	render.JSON(want, request, render.M{"proxies": proxies})
	got := httptest.NewRecorder()
	if !clashWriteProxies(got, request, proxies) {
		t.Fatal("the list was not written")
	}
	if got.Body.String() != want.Body.String() || got.Header().Get("Content-Type") != want.Header().Get("Content-Type") || got.Code != want.Code {
		t.Fatalf("GET /proxies:\n got  %d %q %.300s\n want %d %q %.300s", got.Code, got.Header().Get("Content-Type"), got.Body, want.Code, want.Header().Get("Content-Type"), want.Body)
	}
}

func TestGetProvidersWritesRenderJSONsBytes(t *testing.T) {
	var maps []any
	for i := 0; i < 20; i++ {
		maps = append(maps, map[string]any{"name": fmt.Sprintf("node <%d> & co", i), "type": "ss", "server": "127.0.0.1", "port": 9,
			"cipher": "aes-128-gcm", "password": "p"})
	}
	inline, err := provider.ParseProxyProvider("in <line>", map[string]any{"type": "inline", "payload": maps}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := inline.Initial(); err != nil {
		t.Fatal(err)
	}
	compatible, err := provider.NewCompatibleProvider("default", inline.Proxies()[:3], provider.NewHealthCheck(nil, "", 5000, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	providers := map[string]P.ProxyProvider{inline.Name(): inline, compatible.Name(): compatible}
	request := httptest.NewRequest("GET", "/providers/proxies", nil)
	want := httptest.NewRecorder()
	render.JSON(want, request, render.M{"providers": providers})
	got := httptest.NewRecorder()
	if !clashStreamProviders(got, request, providers) {
		t.Fatal("the providers were not written")
	}
	if got.Body.String() != want.Body.String() || got.Header().Get("Content-Type") != want.Header().Get("Content-Type") || got.Code != want.Code {
		t.Fatalf("GET /providers/proxies:\n got  %.400s\n want %.400s", got.Body, want.Body)
	}
	want, got = httptest.NewRecorder(), httptest.NewRecorder()
	render.JSON(want, request, inline)
	if !clashStreamProvider(got, request, inline) || got.Body.String() != want.Body.String() {
		t.Fatalf("GET /providers/proxies/{name}:\n got  %.400s\n want %.400s", got.Body, want.Body)
	}
}
