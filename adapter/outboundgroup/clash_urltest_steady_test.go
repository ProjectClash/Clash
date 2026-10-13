package outboundgroup

import (
	"context"
	"errors"
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

type switchableNode struct {
	*outbound.Direct
	down *atomic.Bool
}

func (s switchableNode) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if s.down.Load() {
		return nil, errors.New("node down")
	}
	return s.Direct.DialContext(ctx, metadata)
}

func switchable(name string) (C.Proxy, *atomic.Bool) {
	down := &atomic.Bool{}
	direct := outbound.NewDirectWithOption(outbound.DirectOption{Name: name})
	return adapter.NewProxy(switchableNode{Direct: direct, down: down}), down
}

func steadyGroup(t *testing.T, url string, members ...C.Proxy) *URLTest {
	t.Helper()
	compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewURLTest(GroupCommonOption{Name: "auto", URL: url}, URLTestOption{}, members[0], []P.ProxyProvider{compatible})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func measure(t *testing.T, url string, members ...C.Proxy) {
	t.Helper()
	for _, member := range members {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = member.URLTest(ctx, url, nil)
		cancel()
	}
}

func TestAGroupWhoseMembersAllFailKeepsItsChoice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	first, firstDown := switchable("first")
	chosen, chosenDown := switchable("chosen")
	last, lastDown := switchable("last")
	group := steadyGroup(t, server.URL, first, chosen, last)

	firstDown.Store(true)
	lastDown.Store(true)
	measure(t, server.URL, first, chosen, last)
	if got := group.Now(); got != "chosen" {
		t.Fatalf("the only live member is not chosen: %s", got)
	}

	chosenDown.Store(true)
	measure(t, server.URL, first, chosen, last)
	group.fastSingle.Reset()
	if got := group.Now(); got != "chosen" {
		t.Fatalf("with every member down the group moved from chosen to %s", got)
	}

	lastDown.Store(false)
	measure(t, server.URL, last)
	group.fastSingle.Reset()
	if got := group.Now(); got != "last" {
		t.Fatalf("a member came back and the group stayed on a dead one: %s", got)
	}
}

func TestAKeptChoiceIsTheMemberTheGroupHoldsNow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	first, firstDown := switchable("first")
	chosen, _ := switchable("chosen")
	compatible, err := provider.NewCompatibleProvider("members", []C.Proxy{first, chosen}, provider.NewHealthCheck([]C.Proxy{first, chosen}, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewURLTest(GroupCommonOption{Name: "auto", URL: server.URL}, URLTestOption{}, first, []P.ProxyProvider{compatible})
	if err != nil {
		t.Fatal(err)
	}
	firstDown.Store(true)
	measure(t, server.URL, first, chosen)
	if got := group.Now(); got != "chosen" {
		t.Fatalf("the only live member is not chosen: %s", got)
	}

	replacement, replacementDown := switchable("chosen")
	replacementDown.Store(true)
	refreshed, err := provider.NewCompatibleProvider("members", []C.Proxy{first, replacement}, provider.NewHealthCheck([]C.Proxy{first, replacement}, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	group.providers = []P.ProxyProvider{refreshed}
	group.providerVersions = nil
	measure(t, server.URL, first, replacement)
	group.fastSingle.Reset()
	if got := group.fast(false); got != replacement {
		t.Fatalf("the group kept the node object a refresh removed, not the member named %s it holds now", got.Name())
	}
}
