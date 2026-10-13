package route

import (
	"sync/atomic"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)


type ProviderUpdater func(r *http.Request, kind, name string) (status int, message string, handled bool)

var providerUpdater atomic.Pointer[ProviderUpdater]

func SetProviderUpdater(updater ProviderUpdater) {
	if updater == nil {
		providerUpdater.Store(nil)
		return
	}
	providerUpdater.Store(&updater)
}

func clashUpdateProvider(w http.ResponseWriter, r *http.Request, kind, name string) bool {
	updater := providerUpdater.Load()
	if updater == nil {
		return false
	}
	status, message, handled := (*updater)(r, kind, name)
	if !handled {
		return false
	}
	if status == http.StatusNoContent {
		render.NoContent(w, r)
		return true
	}
	render.Status(r, status)
	render.JSON(w, r, newError(message))
	return true
}
