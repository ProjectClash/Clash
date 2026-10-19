package outbound

import (
	"sync/atomic"

	"github.com/ProjectClash/Clash/transport/xhttp"
)

var xhttpDefaultReuse atomic.Pointer[XHTTPReuseSettings]

func XHTTPTunnelReuse() *XHTTPReuseSettings {
	return &XHTTPReuseSettings{
		MaxConnections:   "3",
		HMaxRequestTimes: "600-900",
		HMaxReusableSecs: "1800-3000",
	}
}

func SetXHTTPDefaultReuse(settings *XHTTPReuseSettings) { xhttpDefaultReuse.Store(settings) }

func xhttpReuseSettings(written *XHTTPReuseSettings) *XHTTPReuseSettings {
	if written != nil {
		return written
	}
	return xhttpDefaultReuse.Load()
}

func (v *Vless) ResetNetwork() {
	if v.xhttpClient != nil {
		v.xhttpClient.Reset()
	}
}

func (v *Vless) keepsOwnSessions() bool {
	return v.xhttpClient != nil && v.xhttpClient.Reuses()
}

func (v *Vless) XHTTPReuseConfigs() (upload, download *xhttp.ReuseConfig) {
	if v.xhttpClient == nil {
		return nil, nil
	}
	return v.xhttpClient.ReuseConfigs()
}
