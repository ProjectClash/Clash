package route

import (
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func TestEmbeddedStorageRouterKeepsEveryVerb(t *testing.T) {
	previous := embedMode
	SetEmbedMode(true)
	t.Cleanup(func() { SetEmbedMode(previous) })
	routes := storageRouter().(chi.Routes)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if !routes.Match(chi.NewRouteContext(), method, "/key") {
			t.Fatalf("embedded storage router lost %s; upstream serves all three and nothing "+
				"platform-specific argues against it here", method)
		}
	}
}

func TestStandaloneStorageRouterKeepsMutations(t *testing.T) {
	previous := embedMode
	SetEmbedMode(false)
	t.Cleanup(func() { SetEmbedMode(previous) })
	routes := storageRouter().(chi.Routes)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if !routes.Match(chi.NewRouteContext(), method, "/key") {
			t.Fatalf("standalone storage router lost %s", method)
		}
	}
}
