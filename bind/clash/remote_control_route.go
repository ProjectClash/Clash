package clash

import (
	"encoding/json"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

const controllerAPIVersion = 1

var controllerCapabilities = []string{
	"remote-control-v1",
	"rules-match-v1",
	"provider-update-v1",
	"dns-explain-v1",
	"connection-events-v1",
	"memory-v1",
	"traffic-v1",
	"deviations-v1",
	"mode-stream-v1",
	"stun-v1",
	"provider-health-check-v1",
}

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/remote-control", serveRemoteControlStatus)
			router.Get(prefix+"/capabilities", serveControllerCapabilities)
		}
	})
}

func serveRemoteControlStatus(writer http.ResponseWriter, _ *http.Request) {
	writeControllerJSON(writer, currentRemoteControlStatus())
}

func serveControllerCapabilities(writer http.ResponseWriter, _ *http.Request) {
	writeControllerJSON(writer, struct {
		API          int      `json:"api"`
		Platform     string   `json:"platform"`
		CoreVersion  string   `json:"coreVersion"`
		Capabilities []string `json:"capabilities"`
	}{controllerAPIVersion, controllerPlatformName(currentRuntimeProfile()), Version(), controllerCapabilities})
}

func controllerPlatformName(profile runtimeProfile) string {
	switch profile {
	case runtimeProfileTVOSPacketTunnel:
		return "tvos"
	case runtimeProfileMacOSPacketTunnel, runtimeProfileMacOSApplication:
		return "macos"
	default:
		return "ios"
	}
}

func writeControllerJSON(writer http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, "encoding failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(data)
}
