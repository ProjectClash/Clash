package clash

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	mhttp "github.com/metacubex/http"
	mhttptest "github.com/metacubex/http/httptest"
)

func TestTheHealthCheckRouteStartsTheRoundAndAnswersAtOnce(t *testing.T) {
	probed := make(chan struct{}, 1)
	release := make(chan struct{})
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case probed <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer node.Close()
	defer close(release)

	nodes := []C.Proxy{adapter.NewProxy(outbound.NewDirect())}
	healthCheck := provider.NewHealthCheck(nodes, node.URL, 5000, 0, false, nil)
	large, err := provider.NewCompatibleProvider("large", nodes, healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	defer large.Close()
	restore := swapTunnelProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{"large": large})
	defer restore()

	ask := func(name string) *mhttptest.ResponseRecorder {
		request := mhttptest.NewRequest(mhttp.MethodPost, privateAPIPrefix+"/providers/health-check?name="+name, nil)
		recorder := mhttptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			serveProviderHealthCheck(recorder, request.WithContext(context.Background()))
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("the route for %q held the request", name)
		}
		return recorder
	}

	if got := ask("large").Code; got != mhttp.StatusAccepted {
		t.Fatalf("a running core's provider answered %d, want 202", got)
	}
	select {
	case <-probed:
	case <-time.After(2 * time.Second):
		t.Fatal("the route answered but no round started")
	}
	if got := ask("missing").Code; got != mhttp.StatusNotFound {
		t.Fatalf("an unknown provider answered %d, want 404", got)
	}
	if got := ask("").Code; got != mhttp.StatusBadRequest {
		t.Fatalf("an empty name answered %d, want 400", got)
	}
}
