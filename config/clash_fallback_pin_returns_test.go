package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
)

func TestAFallbacksFixedMemberComesBackWithItsSubscription(t *testing.T) {
	var serving atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !serving.Load() {
			http.Error(w, "not yet", http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, "proxies:\n  - {name: picked, type: direct}\n")
	}))
	defer server.Close()
	home := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(home) })

	cfg, err := Parse([]byte(fmt.Sprintf(`
proxies:
  - {name: alive, type: direct}
proxy-providers:
  sub: {type: http, url: %q, path: ./sub.yaml, interval: 0}
proxy-groups:
  - {name: fb, type: fallback, proxies: [alive], use: [sub], url: 'http://127.0.0.1:1/', interval: 0}
rules:
  - MATCH,fb
`, server.URL+"/sub")))
	if err != nil {
		t.Fatal(err)
	}
	pd := cfg.Providers["sub"]
	_ = pd.Initial()
	group := cfg.Proxies["fb"].Adapter().(*outboundgroup.Fallback)
	group.ForceSet("picked")
	if now := group.Now(); now != "alive" {
		t.Fatalf("before the subscription arrived: now %q; want the first alive member, alive", now)
	}
	serving.Store(true)
	if err := pd.Update(); err != nil {
		t.Fatalf("the subscription's update: %v", err)
	}
	if now := group.Now(); now != "picked" {
		t.Fatalf("after the subscription arrived with it: now %q; want the fixed member back, picked", now)
	}
}
