package clash

import (
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/proxy-delays", serveProxyDelays)
		}
	})
}

func serveProxyDelays(writer mhttp.ResponseWriter, request *mhttp.Request) {
	query := request.URL.Query()
	since, _ := strconv.ParseInt(query.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(query.Get("limit"))
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(mhttp.StatusOK)
	_, _ = io.WriteString(writer, ProxyDelaysPageJSON(since, query.Get("after"), int32(limit)))
}

func (c *APIClient) GetProxyDelays() (string, error) {
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, "/proxy-delays", nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}

func (c *APIClient) GetProxyDelaysPage(since int64, after string, limit int32) (string, error) {
	query := url.Values{}
	if since > 0 {
		query.Set("since", strconv.FormatInt(since, 10))
	}
	if after != "" {
		query.Set("after", after)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(int(limit)))
	}
	suffix := "/proxy-delays"
	if encoded := query.Encode(); encoded != "" {
		suffix += "?" + encoded
	}
	bridgedValue0, bridgedErr := c.privateRequest(http.MethodGet, suffix, nil)
	return bridgeSafeString(bridgedValue0), bridgeSafeError(bridgedErr)
}
