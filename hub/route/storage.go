package route

import (
	"encoding/json"
	"io"

	"github.com/ProjectClash/Clash/component/profile/cachefile"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func storageRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/{key}", getStorage)
	r.Put("/{key}", setStorage)
	r.Delete("/{key}", deleteStorage)
	return r
}

func getStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data := cachefile.Cache().GetStorage(key)
	w.Header().Set("Content-Type", "application/json")
	if len(data) == 0 {
		w.Write([]byte("null"))
		return
	}
	w.Write(data)
}

const storageMaxBodyBytes = 1024 * 1024

func setStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data, err := io.ReadAll(io.LimitReader(r.Body, storageMaxBodyBytes+1))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if len(data) > storageMaxBodyBytes {
		render.Status(r, http.StatusRequestEntityTooLarge)
		render.JSON(w, r, newError("payload exceeds 1MB limit"))
		return
	}
	if !json.Valid(data) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	cachefile.Cache().SetStorage(key, data)
	render.NoContent(w, r)
}

func deleteStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	cachefile.Cache().DeleteStorage(key)
	render.NoContent(w, r)
}
