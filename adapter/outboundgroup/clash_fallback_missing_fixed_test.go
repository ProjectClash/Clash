package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

type downable struct {
	*outbound.Direct
	down *atomic.Bool
}

func (d downable) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if d.down.Load() {
		return nil, errors.New("the node is down")
	}
	return d.Direct.DialContext(ctx, metadata)
}

func fallbackOf(t *testing.T, url string, n int) (*Fallback, []C.Proxy, []*atomic.Bool) {
	t.Helper()
	var members []C.Proxy
	var down []*atomic.Bool
	for i := 0; i < n; i++ {
		d := &atomic.Bool{}
		down = append(down, d)
		members = append(members, adapter.NewProxy(downable{outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("member %d", i)}), d}))
	}
	compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewFallback(GroupCommonOption{Name: "g", URL: url}, FallbackOption{}, adapter.NewProxy(outbound.NewCompatible()), []P.ProxyProvider{compatible})
	if err != nil {
		t.Fatal(err)
	}
	return group, members, down
}

func testEach(t *testing.T, members []C.Proxy, url string) {
	t.Helper()
	for _, m := range members {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = m.URLTest(ctx, url, nil)
		cancel()
	}
}

func TestAFallbackPassesOverAFixedMemberItDoesNotHave(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	group, members, down := fallbackOf(t, server.URL, 3)
	down[0].Store(true)
	testEach(t, members, server.URL)
	group.ForceSet("a member renamed since")
	if now := group.Now(); now != members[1].Name() {
		t.Errorf("now %q; want the first alive member, %q", now, members[1].Name())
	}
	if fixed := group.selected.Load(); fixed != "a member renamed since" {
		t.Errorf("fixed %q; want the name kept, for a subscription that lists it later", fixed)
	}
	if proxy := group.findAliveProxy(true); proxy.Name() != members[1].Name() {
		t.Errorf("a dial goes through %q; want %q", proxy.Name(), members[1].Name())
	}
}

func TestAFallbackKeepsAFixedMemberItHas(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	group, members, _ := fallbackOf(t, server.URL, 3)
	testEach(t, members, server.URL)
	group.ForceSet(members[2].Name())
	if now := group.Now(); now != members[2].Name() {
		t.Errorf("now %q; want the fixed member, %q", now, members[2].Name())
	}
	if fixed := group.selected.Load(); fixed != members[2].Name() {
		t.Errorf("fixed %q; want %q", fixed, members[2].Name())
	}
}
