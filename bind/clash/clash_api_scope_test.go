package clash

import (
	"context"

	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type fakeClashAPI struct {
	mu       sync.Mutex
	refuse   []string
	dialed   map[string]int
	server   *http.Server
	listener net.Listener
}

func startFakeClashAPI(t *testing.T, socketPath string) *fakeClashAPI {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	api := &fakeClashAPI{dialed: make(map[string]int), listener: listener}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		target := request.URL.RequestURI()
		if request.Header.Get("Upgrade") == "" {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("{}"))
			return
		}
		if api.refusing(target) {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		api.recordDial(target)
		go api.publish(connection)
	})
	api.server = &http.Server{Handler: mux}
	go func() { _ = api.server.Serve(listener) }()
	t.Cleanup(func() {
		_ = api.server.Close()
		_ = listener.Close()
	})
	return api
}

func (a *fakeClashAPI) publish(connection *websocket.Conn) {
	defer connection.CloseNow()
	for {
		writeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := connection.Write(writeCtx, websocket.MessageText,
			[]byte(`{"up":0,"down":0,"upTotal":0,"downTotal":0}`))
		cancel()
		if err != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (a *fakeClashAPI) refusing(target string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, prefix := range a.refuse {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

func (a *fakeClashAPI) recordDial(target string) {
	a.mu.Lock()
	a.dialed[target]++
	a.mu.Unlock()
}

func (a *fakeClashAPI) refuseAll(prefixes ...string) {
	a.mu.Lock()
	a.refuse = append(a.refuse, prefixes...)
	a.mu.Unlock()
}

func (a *fakeClashAPI) dialCount(target string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dialed[target]
}

func (c *APIClient) streamConnections() map[string]*websocket.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]*websocket.Conn)
	if c.session == nil {
		return out
	}
	for _, stream := range c.session.streams {
		out[stream.path] = stream.conn
	}
	return out
}

type scopeHandler struct {
	once         sync.Once
	connected    chan struct{}
	disconnected chan string
	traffic      chan string
}

func newScopeHandler() *scopeHandler {
	return &scopeHandler{
		connected:    make(chan struct{}),
		disconnected: make(chan string, 1),
		traffic:      make(chan string, 16),
	}
}

func (h *scopeHandler) Connected() { h.once.Do(func() { close(h.connected) }) }
func (h *scopeHandler) Disconnected(message string) {
	select {
	case h.disconnected <- message:
	default:
	}
}
func (h *scopeHandler) WriteTraffic(message string) {
	select {
	case h.traffic <- message:
	default:
	}
}
func (h *scopeHandler) WriteMemory(string)      {}
func (h *scopeHandler) WriteLogs(string)        {}
func (h *scopeHandler) WriteConnections(string) {}
func (h *scopeHandler) WriteMode(string)        {}

func connectedScopeClient(t *testing.T, onlyProxy bool) (*APIClient, *fakeClashAPI, *scopeHandler) {
	t.Helper()
	path := shortClashSocketPath(t)
	api := startFakeClashAPI(t, path)
	options := &APIClientOptions{OnlyStatisticsProxy: onlyProxy}
	options.AddCommand(CommandStatus)
	options.AddCommand(CommandLog)
	options.AddCommand(CommandConnections)
	handler := newScopeHandler()
	client, err := NewAPIClientWithOptions(path, handler, options)
	if err != nil {
		t.Fatalf("NewAPIClientWithOptions: %v", err)
	}
	t.Cleanup(client.Close)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return client, api, handler
}

func drainTraffic(handler *scopeHandler) {
	for {
		select {
		case <-handler.traffic:
		default:
			return
		}
	}
}

func awaitTraffic(t *testing.T, handler *scopeHandler, why string) {
	t.Helper()
	select {
	case <-handler.traffic:
	case <-time.After(3 * time.Second):
		t.Fatalf("no traffic frame arrived %s", why)
	}
}

func TestSetOnlyStatisticsProxyChangesScopeOnALiveConnection(t *testing.T) {
	client, _, handler := connectedScopeClient(t, false)
	awaitTraffic(t, handler, "before the scope change")

	if before := client.streamConnections(); before["/traffic"] == nil {
		t.Fatalf("expected a plain /traffic stream, got %v", pathsOf(before))
	}
	if err := client.SetOnlyStatisticsProxy(true); err != nil {
		t.Fatalf("SetOnlyStatisticsProxy: %v", err)
	}

	after := client.streamConnections()
	if after["/traffic?only-proxy=true"] == nil {
		t.Fatalf("traffic stream did not move to the proxy-only path: %v", pathsOf(after))
	}
	if after["/traffic"] != nil {
		t.Fatalf("the old traffic stream is still subscribed: %v", pathsOf(after))
	}
	drainTraffic(handler)
	awaitTraffic(t, handler, "after the scope change")

	select {
	case message := <-handler.disconnected:
		t.Fatalf("the control session was torn down: %q", message)
	default:
	}
}

func TestSetOnlyStatisticsProxyLeavesTheOtherStreamsUntouched(t *testing.T) {
	client, api, handler := connectedScopeClient(t, false)
	awaitTraffic(t, handler, "before the scope change")
	before := client.streamConnections()

	if err := client.SetOnlyStatisticsProxy(true); err != nil {
		t.Fatalf("SetOnlyStatisticsProxy: %v", err)
	}
	after := client.streamConnections()

	for _, path := range []string{"/memory", "/logs?level=info", "/connections?interval=1000"} {
		if before[path] == nil {
			t.Fatalf("%s was not subscribed to begin with: %v", path, pathsOf(before))
		}
		if before[path] != after[path] {
			t.Fatalf("%s was re-dialled across a traffic-scope change", path)
		}
		if count := api.dialCount(path); count != 1 {
			t.Fatalf("%s was dialled %d times, want 1", path, count)
		}
	}
}

func TestSetOnlyStatisticsProxyIsIdempotent(t *testing.T) {
	client, api, handler := connectedScopeClient(t, true)
	awaitTraffic(t, handler, "before the no-op")
	before := client.streamConnections()

	if err := client.SetOnlyStatisticsProxy(true); err != nil {
		t.Fatalf("SetOnlyStatisticsProxy: %v", err)
	}

	after := client.streamConnections()
	if before["/traffic?only-proxy=true"] != after["/traffic?only-proxy=true"] {
		t.Fatal("setting the current value re-dialled the traffic stream")
	}
	if count := api.dialCount("/traffic?only-proxy=true"); count != 1 {
		t.Fatalf("traffic was dialled %d times, want 1", count)
	}
}

func TestSetOnlyStatisticsProxyKeepsTheOldStreamWhenTheNewOneFails(t *testing.T) {
	client, api, handler := connectedScopeClient(t, false)
	awaitTraffic(t, handler, "before the failed change")
	before := client.streamConnections()

	api.refuseAll("/traffic?only-proxy=true")
	err := client.SetOnlyStatisticsProxy(true)
	if err == nil {
		t.Fatal("a refused re-subscribe reported success")
	}

	after := client.streamConnections()
	if before["/traffic"] != after["/traffic"] {
		t.Fatalf("the working traffic stream was dropped for a dial that failed: %v", pathsOf(after))
	}
	drainTraffic(handler)
	awaitTraffic(t, handler, "after the failed change")
	select {
	case message := <-handler.disconnected:
		t.Fatalf("a failed re-subscribe tore down the session: %q", message)
	default:
	}

	if err := client.SetOnlyStatisticsProxy(true); err == nil {
		t.Fatal("the failed scope was recorded as if it had been applied")
	}
}

func pathsOf(streams map[string]*websocket.Conn) []string {
	out := make([]string, 0, len(streams))
	for path := range streams {
		out = append(out, path)
	}
	return out
}
