package clash

import "github.com/metacubex/http"

const tunnelHTTP2RequestBodyScratch = 64 << 10

func applyHTTP2RequestBodyScratch(profile runtimeProfile) {
	if profile.inheritsIOSPacketTunnelBehavior() {
		http.SetHTTP2StreamingBodyScratchMax(tunnelHTTP2RequestBodyScratch)
		http.SetHTTP2StreamingBodyScratchOnDemand(true)
		return
	}
	http.SetHTTP2StreamingBodyScratchMax(0)
	http.SetHTTP2StreamingBodyScratchOnDemand(false)
}
