package clash

import (
	"encoding/json"
	"errors"
	"io"
	"mime"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

const proxyShareMaximumRequestBytes = 2048

type proxyShareRequest struct {
	Port     int32  `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/proxy-share", serveProxyShareStatus)
			router.Put(prefix+"/proxy-share", appGroupSocketOnly(serveProxyShareStart))
			router.Delete(prefix+"/proxy-share", appGroupSocketOnly(serveProxyShareStop))
		}
	})
}

func serveProxyShareStatus(writer http.ResponseWriter, _ *http.Request) {
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Clash service is not running", http.StatusServiceUnavailable)
		return
	}
	writeProxyShareStatus(writer, service.ProxyShareStatusJSON())
}

func serveProxyShareStart(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(writer, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if request.ContentLength > proxyShareMaximumRequestBytes {
		http.Error(writer, "proxy-share request too large", http.StatusRequestEntityTooLarge)
		return
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, proxyShareMaximumRequestBytes+1))
	decoder.DisallowUnknownFields()
	var input proxyShareRequest
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid proxy-share request", http.StatusBadRequest)
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(writer, "invalid proxy-share request", http.StatusBadRequest)
		return
	}
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Clash service is not running", http.StatusServiceUnavailable)
		return
	}
	if err := service.StartProxyShare(input.Port, input.Username, input.Password); err != nil {
		var portUnavailable proxySharePortUnavailableError
		if errors.As(err, &portUnavailable) {
			http.Error(writer, portUnavailable.Error(), http.StatusConflict)
			return
		}
		http.Error(writer, "proxy share rejected", http.StatusUnprocessableEntity)
		return
	}
	writeProxyShareStatus(writer, service.ProxyShareStatusJSON())
}

func serveProxyShareStop(writer http.ResponseWriter, _ *http.Request) {
	service := currentCoreService()
	if service == nil {
		http.Error(writer, "Clash service is not running", http.StatusServiceUnavailable)
		return
	}
	_ = service.StopProxyShare()
	writeProxyShareStatus(writer, service.ProxyShareStatusJSON())
}

func writeProxyShareStatus(writer http.ResponseWriter, payload string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, payload)
}
