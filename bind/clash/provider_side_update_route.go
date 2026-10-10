package clash

import (
	"io"
	"mime"
	"strings"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Put(prefix+"/providers/side-update", appGroupSocketOnly(serveProviderSideUpdate))
		}
	})
}

func serveProviderSideUpdate(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, mediaTypeError := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaTypeError != nil || mediaType != "application/octet-stream" {
		http.Error(writer, "content type must be application/octet-stream", http.StatusUnsupportedMediaType)
		return
	}
	kind := request.URL.Query().Get("kind")
	name := request.URL.Query().Get("name")
	expected := request.URL.Query().Get("expect")
	if (kind != "proxy" && kind != "rule") || !validProviderSideUpdateName(name) || !validConfigurationSHA256(expected, true) {
		http.Error(writer, "invalid provider selector", http.StatusBadRequest)
		return
	}
	if request.ContentLength > maximumProviderResourceBytes {
		http.Error(writer, "provider payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, int64(maximumProviderResourceBytes)+1))
	if err != nil {
		http.Error(writer, "invalid provider payload", http.StatusBadRequest)
		return
	}
	if len(payload) == 0 {
		http.Error(writer, "provider payload is empty", http.StatusBadRequest)
		return
	}
	if len(payload) > maximumProviderResourceBytes {
		http.Error(writer, "provider payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Clash service is not running", http.StatusServiceUnavailable)
		return
	}
	if err := service.sideUpdateProvider(kind, name, payload, expected); err != nil {
		status, body := sideUpdateRefusal(err)
		http.Error(writer, body, status)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func sideUpdateRefusal(err error) (int, string) {
	message := err.Error()
	if strings.HasPrefix(message, SideUpdateDeferredPrefix) || strings.HasPrefix(message, SideUpdateStalePrefix) {
		return http.StatusConflict, message
	}
	return http.StatusUnprocessableEntity, "provider side update rejected"
}

func validConfigurationSHA256(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validProviderSideUpdateName(name string) bool {
	return name != "" && len(name) <= 512 && strings.IndexFunc(name, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) < 0
}
