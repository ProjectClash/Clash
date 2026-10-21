package clash

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

var privateRouteTable = []struct{ method, suffix string }{
	{http.MethodGet, "/traffic"},
	{http.MethodGet, "/memory"},
	{http.MethodGet, "/mode"},
	{http.MethodPatch, "/configs/mode"},
	{http.MethodGet, "/connections/events"},
	{http.MethodGet, "/dns/explain"},
	{http.MethodGet, "/deviations"},
	{http.MethodGet, "/proxy-share"},
	{http.MethodPut, "/proxy-share"},
	{http.MethodDelete, "/proxy-share"},
	{http.MethodPut, "/providers/side-update"},
	{http.MethodPost, "/providers/health-check"},
	{http.MethodPost, "/stun"},
	{http.MethodGet, "/remote-control"},
	{http.MethodGet, "/capabilities"},
	{http.MethodGet, "/rules/match"},
	{http.MethodGet, "/proxy-delays"},
	{http.MethodGet, "/proxies-page"},
	{http.MethodGet, "/group-members"},
	{http.MethodGet, "/group-members-search"},
	{http.MethodGet, "/proxy-lookup"},
	{http.MethodGet, "/proxies-summary"},
	{http.MethodGet, "/rules-page"},
	{http.MethodGet, "/rules-hits"},
	{http.MethodGet, "/provider-nodes"},
	{http.MethodGet, "/proxies-search"},
	{http.MethodPost, "/dns/script-query"},
}

func TestPrivateRoutesAnswerUnderClashPrefix(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, addr), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	client := &http.Client{Timeout: 5 * time.Second}
	for _, route := range privateRouteTable {
		statuses := map[string]int{}
		for _, prefix := range privateRoutePrefixes {
			request, err := http.NewRequest(route.method, "http://"+addr+prefix+route.suffix, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("%s %s%s: %v", route.method, prefix, route.suffix, err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNotFound {
				t.Errorf("%s %s%s is not registered", route.method, prefix, route.suffix)
			}
			statuses[prefix] = response.StatusCode
		}
	}
	response, err := client.Get("http://" + addr + privateAPIPrefix + "/no-such-route")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown private route = HTTP %d, want 404", response.StatusCode)
	}
}

func TestPrivateRoutesRegisterThroughThePrefixLoop(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	literal := regexp.MustCompile(`"/clash/v1`)
	registration := regexp.MustCompile(`router\.(Get|Put|Post|Patch|Delete)\(prefix\+"(/[^"]*)"`)
	registered := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if name != "clash_api.go" && literal.Match(source) {
			t.Errorf("%s hard-codes a private prefix; use privateRoutePrefixes or APIClient.privatePath", name)
		}
		for _, match := range registration.FindAllSubmatch(source, -1) {
			registered[string(match[1])+" "+string(match[2])] = true
		}
	}
	for _, route := range privateRouteTable {
		key := map[string]string{
			http.MethodGet: "Get", http.MethodPut: "Put", http.MethodPost: "Post",
			http.MethodPatch: "Patch", http.MethodDelete: "Delete",
		}[route.method] + " " + route.suffix
		if !registered[key] {
			t.Errorf("%s %s is in the table but not registered through the prefix loop", route.method, route.suffix)
		}
		delete(registered, key)
	}
	for key := range registered {
		t.Errorf("%s is registered but missing from privateRouteTable", key)
	}
}

type extensionServer struct {
	mu    sync.Mutex
	paths []string
}

func (s *extensionServer) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, r.Method+" "+r.URL.Path)
}

func (s *extensionServer) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func (s *extensionServer) count(prefix string) int {
	n := 0
	for _, path := range s.asked() {
		if strings.Contains(path, " "+prefix+"/") {
			n++
		}
	}
	return n
}

func (s *extensionServer) serve(prefixes ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, "{}")
			return
		}
		for _, prefix := range prefixes {
			switch strings.TrimPrefix(r.URL.Path, prefix) {
			case "/traffic", "/deviations":
				if strings.HasPrefix(r.URL.Path, prefix) {
					_, _ = io.WriteString(w, `{"up":1,"down":2,"upTotal":3,"downTotal":4}`)
					return
				}
			case "/providers/side-update":
				if strings.HasPrefix(r.URL.Path, prefix) && r.Method == http.MethodPut {
					_, _ = io.Copy(io.Discard, r.Body)
					w.WriteHeader(http.StatusOK)
					return
				}
			case "/stun":
				if strings.HasPrefix(r.URL.Path, prefix) && r.Method == http.MethodPost {
					w.Header().Set("Content-Type", "application/x-ndjson")
					w.WriteHeader(http.StatusOK)
					return
				}
			case "/mode", "/connections/events":
				if strings.HasPrefix(r.URL.Path, prefix) {
					conn, err := websocket.Accept(w, r, nil)
					if err != nil {
						return
					}
					defer conn.CloseNow()
					_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"mode":"rule","allowLan":false}`))
					_, _, _ = conn.Read(r.Context())
					return
				}
			}
		}
		http.NotFound(w, r)
	}
}

func extensionClient(t *testing.T, server *extensionServer, handler APIClientHandler, prefixes []string, commands ...int32) *APIClient {
	t.Helper()
	options := &APIClientOptions{}
	for _, command := range commands {
		options.AddCommand(command)
	}
	client, err := NewAPIClientWithOptions("/unused-prefix-fixture", handler, options)
	if err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewServer(server.serve(prefixes...))
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", fixture.Listener.Addr().String())
	}}
	client.httpClient = &http.Client{Transport: transport}
	t.Cleanup(func() { client.Close(); transport.CloseIdleConnections(); fixture.Close() })
	return client
}

func TestPrivateRequestsPreferTheCurrentPrefixOnACurrentExtension(t *testing.T) {
	server := &extensionServer{}
	handler := newRecordingClashAPIHandler()
	client := extensionClient(t, server, handler, []string{privateAPIPrefix}, CommandMode)

	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handler.connected:
	case <-time.After(5 * time.Second):
		t.Fatal("the session never connected")
	}
	if _, err := client.GetTraffic(); err != nil {
		t.Fatal(err)
	}
	if err := client.sideUpdateProvider("rule", "reject", []byte("DOMAIN,example.invalid\n"), ""); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateRequestMissingDoesNotRetry(t *testing.T) {
	server := &extensionServer{}
	client := extensionClient(t, server, newRecordingClashAPIHandler(), nil)

	_, err := client.GetTraffic()
	if err == nil || !strings.Contains(err.Error(), privateAPIPrefix+"/traffic") || !isClashAPINotFound(err) {
		t.Fatalf("GetTraffic = %v, want a 404 naming %s/traffic", err, privateAPIPrefix)
	}
	want := []string{"GET /clash/v1/traffic"}
	if got := server.asked(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("asked %v, want %v", got, want)
	}
}

type stubSTUNHandler struct{}

func (stubSTUNHandler) OnProgress(*STUNTestProgress) {}
func (stubSTUNHandler) OnResult(*STUNTestResult)     {}
func (stubSTUNHandler) OnError(string)               {}

func TestEveryPrivateStreamUsesClashPrefix(t *testing.T) {
	server := &extensionServer{}
	handler := newRecordingClashAPIHandler()
	client := extensionClient(t, server, handler, []string{privateAPIPrefix}, CommandMode, CommandConnectionEvents)
	client.SetConnectionEventsWriter(&recordingConnectionEventsWriter{})

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect against an Clash Extension: %v", err)
	}
	select {
	case <-handler.connected:
	case <-time.After(5 * time.Second):
		t.Fatalf("the session never connected; asked %v", server.asked())
	}
	for _, want := range []string{"GET /clash/v1/mode", "GET /clash/v1/connections/events"} {
		found := false
		for _, got := range server.asked() {
			found = found || got == want
		}
		if !found {
			t.Fatalf("%s was never dialled; asked %v", want, server.asked())
		}
	}
}

func TestConcurrentPrivateRequestsUseClashPrefix(t *testing.T) {
	for round := 0; round < 20; round++ {
		server := &extensionServer{}
		client := extensionClient(t, server, newRecordingClashAPIHandler(), []string{privateAPIPrefix})
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := client.GetTraffic(); err != nil {
					errs <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: a concurrent first request failed against an Clash Extension: %v", round, err)
		}
	}
}
