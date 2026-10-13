package clash

import (
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Post(prefix+"/providers/health-check", serveProviderHealthCheck)
		}
	})
}

func serveProviderHealthCheck(writer http.ResponseWriter, request *http.Request) {
	name := request.URL.Query().Get("name")
	if !validProviderSideUpdateName(name) {
		http.Error(writer, "invalid provider name", http.StatusBadRequest)
		return
	}
	provider, ok := tunnel.Providers()[name]
	if !ok {
		http.Error(writer, "proxy provider not found", http.StatusNotFound)
		return
	}
	go provider.HealthCheck()
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusAccepted)
}
