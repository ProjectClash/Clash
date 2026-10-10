package route

import (
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func TestEmbeddedUpgradeRouterClosesOnlyTheBinaryReplacement(t *testing.T) {
	previous := embedMode
	SetEmbedMode(true)
	t.Cleanup(func() { SetEmbedMode(previous) })

	routes, ok := upgradeRouter().(chi.Routes)
	if !ok {
		t.Fatal("upgrade router does not expose route metadata")
	}
	if routes.Match(chi.NewRouteContext(), http.MethodPost, "/") {
		t.Fatal("embedded upgrade router exposes POST /; code signing forbids replacing the " +
			"binary on Apple, so this one is a platform fact and must stay closed")
	}
	if !routes.Match(chi.NewRouteContext(), http.MethodPost, "/ui") {
		t.Fatal("embedded upgrade router lost POST /ui; the core downloads the dashboard " +
			"unprompted on the start path, so refusing the route only removes the safer half")
	}
	if routes.Match(chi.NewRouteContext(), http.MethodPost, "/geo") != geoUpdaterAllowed {
		t.Fatalf("POST /geo presence must follow geoUpdaterAllowed (%v), not embed mode",
			geoUpdaterAllowed)
	}
}

func TestStandaloneUpgradeRouterKeepsUpstreamRoutes(t *testing.T) {
	previous := embedMode
	SetEmbedMode(false)
	t.Cleanup(func() { SetEmbedMode(previous) })

	routes := upgradeRouter().(chi.Routes)
	for _, path := range []string{"/", "/geo", "/ui"} {
		if !routes.Match(chi.NewRouteContext(), http.MethodPost, path) {
			t.Fatalf("standalone upgrade router lost POST %s", path)
		}
	}
}
