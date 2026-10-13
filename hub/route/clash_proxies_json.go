package route

import (
	"sort"

	"github.com/ProjectClash/Clash/adapter"
	adapterprovider "github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func clashWriteProxies(w http.ResponseWriter, r *http.Request, proxies map[string]C.Proxy) bool {
	b, err := adapter.AppendProxiesJSON([]byte(`{"proxies":`), proxies)
	if err != nil {
		return false
	}
	b = append(b, "}\n"...)
	w.Header().Set("Content-Type", "application/json")
	if status, ok := r.Context().Value(render.StatusCtxKey).(int); ok {
		w.WriteHeader(status)
	}
	_, _ = w.Write(b)
	return true
}

func clashStreamProxies(w http.ResponseWriter, r *http.Request, proxies map[string]C.Proxy, library C.ProxyLibrary) {
	w.Header().Set("Content-Type", "application/json")
	if status, ok := r.Context().Value(render.StatusCtxKey).(int); ok {
		w.WriteHeader(status)
	}
	if _, err := w.Write([]byte(`{"proxies":`)); err != nil {
		return
	}
	if err := adapter.WriteProxiesJSON(w, proxies, library); err != nil {
		return
	}
	_, _ = w.Write([]byte("}\n"))
}

func clashStreamProviders(w http.ResponseWriter, r *http.Request, providers map[string]P.ProxyProvider) bool {
	names := make([]string, 0, len(providers))
	for name, provider := range providers {
		if !adapterprovider.ClashProviderWritable(provider) {
			return false
		}
		names = append(names, name)
	}
	sort.Strings(names)
	w.Header().Set("Content-Type", "application/json")
	if status, ok := r.Context().Value(render.StatusCtxKey).(int); ok {
		w.WriteHeader(status)
	}
	if _, err := w.Write([]byte(`{"providers":{`)); err != nil {
		return true
	}
	for i, name := range names {
		key := adapter.AppendJSONString(nil, name)
		if i > 0 {
			key = append([]byte{','}, key...)
		}
		if _, err := w.Write(append(key, ':')); err != nil {
			return true
		}
		if _, err := adapterprovider.ClashWriteProviderJSON(w, providers[name]); err != nil {
			return true
		}
	}
	_, _ = w.Write([]byte("}}\n"))
	return true
}

func clashStreamProvider(w http.ResponseWriter, r *http.Request, provider P.ProxyProvider) bool {
	if !adapterprovider.ClashProviderWritable(provider) {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	if status, ok := r.Context().Value(render.StatusCtxKey).(int); ok {
		w.WriteHeader(status)
	}
	if _, err := adapterprovider.ClashWriteProviderJSON(w, provider); err != nil {
		return true
	}
	_, _ = w.Write([]byte("\n"))
	return true
}
