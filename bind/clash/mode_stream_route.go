package clash

import (
	"encoding/json"
	"net"
	"sync"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/component/profile/cachefile"
	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/listener"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

type runtimeSwitches struct {
	Mode     string            `json:"mode"`
	AllowLan bool              `json:"allow-lan"`
	Selected map[string]string `json:"selected"`
}

func currentRuntimeSwitches() runtimeSwitches {
	return runtimeSwitches{
		Mode:     tunnel.Mode().String(),
		AllowLan: listener.AllowLan(),
		Selected: currentSelections(),
	}
}

func currentSelections() map[string]string {
	selections := map[string]string{}
	for name, proxy := range tunnel.Proxies() {
		selector, manual := proxy.Adapter().(*outboundgroup.Selector)
		if !manual {
			continue
		}
		selections[name] = selector.Now()
	}
	return selections
}

var modeSubscribers = struct {
	sync.Mutex
	next    int
	streams map[int]chan runtimeSwitches
}{streams: map[int]chan runtimeSwitches{}}

func init() {
	installRuntimeSwitchSeams()
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/mode", serveModeStream)
		}
	})
}

func installRuntimeSwitchSeams() {
	tunnel.SetModeObserver(func(tunnel.TunnelMode) { publishRuntimeSwitches() })
	listener.SetAllowLanObserver(func(bool) { publishRuntimeSwitches() })
	cachefile.SetSelectedObserver(func(string, string) { publishRuntimeSwitches() })
}

var parseWindow struct {
	sync.Mutex
	inFlight int
	parses   int
	muted    int
}

const parserModeWritesPerParse = 2

func parseRawConfigQuietly(raw *config.RawConfig) (*config.Config, error) {
	return insideParseWindow(func() (*config.Config, error) { return config.ParseRawConfig(raw) })
}

func insideParseWindow(parse func() (*config.Config, error)) (*config.Config, error) {
	parseWindow.Lock()
	parseWindow.inFlight++
	parseWindow.parses++
	parseWindow.Unlock()
	defer func() {
		parseWindow.Lock()
		parseWindow.inFlight--
		republish := false
		if parseWindow.inFlight == 0 {
			republish = parseWindow.muted > parseWindow.parses*parserModeWritesPerParse
			parseWindow.parses, parseWindow.muted = 0, 0
		}
		parseWindow.Unlock()
		if republish {
			publishRuntimeSwitches()
		}
	}()
	return parse()
}

func publishRuntimeSwitches() {
	parseWindow.Lock()
	if parseWindow.inFlight > 0 {
		parseWindow.muted++
		parseWindow.Unlock()
		return
	}
	parseWindow.Unlock()
	switches := currentRuntimeSwitches()
	modeSubscribers.Lock()
	defer modeSubscribers.Unlock()
	for _, stream := range modeSubscribers.streams {
		select {
		case stream <- switches:
		default:
			select {
			case <-stream:
			default:
			}
			select {
			case stream <- switches:
			default:
			}
		}
	}
}

func serveModeStream(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Upgrade") == "websocket" {
		connection, err := route.UpgradeWebSocket(request, writer)
		if err != nil {
			return
		}
		serveModeWebSocket(request, connection)
		return
	}

	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	stream, release := subscribeRuntimeSwitches()
	defer release()

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(writer)
	send := func(switches runtimeSwitches) bool {
		if err := encoder.Encode(switches); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !send(currentRuntimeSwitches()) {
		return
	}
	for {
		select {
		case switches := <-stream:
			if !send(switches) {
				return
			}
		case <-request.Context().Done():
			return
		}
	}
}

func serveModeWebSocket(request *http.Request, connection net.Conn) {
	defer connection.Close()

	stream, release := subscribeRuntimeSwitches()
	defer release()

	send := func(switches runtimeSwitches) bool {
		payload, err := json.Marshal(switches)
		if err != nil {
			return false
		}
		return route.WriteWebSocketText(connection, payload) == nil
	}
	if !send(currentRuntimeSwitches()) {
		return
	}
	for {
		select {
		case switches := <-stream:
			if !send(switches) {
				return
			}
		case <-request.Context().Done():
			return
		}
	}
}

func subscribeRuntimeSwitches() (<-chan runtimeSwitches, func()) {
	stream := make(chan runtimeSwitches, 1)
	modeSubscribers.Lock()
	id := modeSubscribers.next
	modeSubscribers.next++
	modeSubscribers.streams[id] = stream
	modeSubscribers.Unlock()
	return stream, func() {
		modeSubscribers.Lock()
		delete(modeSubscribers.streams, id)
		modeSubscribers.Unlock()
	}
}
