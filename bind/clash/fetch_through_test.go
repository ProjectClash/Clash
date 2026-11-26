package clash

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/component/ca"
	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
	mhttp "github.com/metacubex/http"
)

type connectProxy struct {
	port    int
	mu      sync.Mutex
	targets []string
}

func (p *connectProxy) asked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func newConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	proxy := &connectProxy{port: listener.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				reader := bufio.NewReader(client)
				request, err := http.ReadRequest(reader)
				if err != nil || request.Method != http.MethodConnect {
					return
				}
				proxy.mu.Lock()
				proxy.targets = append(proxy.targets, request.Host)
				proxy.mu.Unlock()
				upstream, err := net.Dial("tcp", request.Host)
				if err != nil {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer upstream.Close()
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, reader); done <- struct{}{} }()
				go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return proxy
}

func fetchThroughYAML(proxy *connectProxy) string {
	return fmt.Sprintf(`
mode: rule
log-level: info
proxies:
  - {name: "新加坡 01", type: http, server: 127.0.0.1, port: %d}
  - {name: dead, type: http, server: 127.0.0.1, port: 1}
  - {name: dns-out, type: dns}
  - {name: again, type: rematch, target-rematch-name: again}
proxy-groups:
  - {name: 节点选择, type: select, proxies: ["新加坡 01"]}
  - {name: 拒绝组, type: select, proxies: [REJECT]}
rules:
  - MATCH,REJECT
`, proxy.port)
}

func fetchThroughOrigin(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	origin := httptest.NewTLSServer(handler)
	t.Cleanup(origin.Close)
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	if err := ca.AddCertificate(string(block)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.ResetCertificate)
	return origin
}

func fetchThroughJSON(t *testing.T, proxy, url string, timeoutMilliseconds int64, userAgent string) string {
	t.Helper()
	request := map[string]any{"proxy": proxy, "url": url, "timeoutMilliseconds": timeoutMilliseconds}
	if userAgent != "" {
		request["userAgent"] = userAgent
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

type fetchThroughWire struct {
	Status  *int     `json:"status"`
	Body    *string  `json:"body"`
	Chain   []string `json:"chain"`
	Failure string   `json:"failure"`
	Message string   `json:"message"`
}

func decodeFetchThrough(t *testing.T, answer string) fetchThroughWire {
	t.Helper()
	var decoded fetchThroughWire
	if err := json.Unmarshal([]byte(answer), &decoded); err != nil {
		t.Fatalf("answer %q is not JSON: %v", answer, err)
	}
	if decoded.Chain == nil {
		t.Fatalf("answer %s has no chain; the App reads it on every answer", answer)
	}
	return decoded
}

func fetchThrough(t *testing.T, client *APIClient, request string) fetchThroughWire {
	t.Helper()
	answer, err := client.FetchThrough(request)
	if err != nil {
		t.Fatalf("FetchThrough(%s): %v", request, err)
	}
	return decodeFetchThrough(t, answer)
}

func wantFetched(t *testing.T, got fetchThroughWire, status int, body string, chain ...string) {
	t.Helper()
	if got.Failure != "" || got.Status == nil || *got.Status != status || got.Body == nil || *got.Body != body ||
		fmt.Sprint(got.Chain) != fmt.Sprint(chain) {
		t.Fatalf("answer = %+v (status %v, body %v), want status %d, body %q, chain %v",
			got, deref(got.Status), deref(got.Body), status, body, chain)
	}
}

func wantFailure(t *testing.T, got fetchThroughWire, failure string) {
	t.Helper()
	if got.Failure != failure || got.Status != nil || got.Body != nil || got.Message == "" {
		t.Fatalf("answer = %+v (status %v), want failure %q with the core's words and no status or body",
			got, deref(got.Status), failure)
	}
}

func deref[T any](value *T) any {
	if value == nil {
		return nil
	}
	return *value
}

func TestFetchThroughReachesTheOriginThroughTheNamedNode(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	type seen struct{ userAgent, cookie, connection, method, encoding, authorization string }
	requests := make(chan seen, 1)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		requests <- seen{request.Header.Get("User-Agent"), request.Header.Get("Cookie"), request.Header.Get("Connection"), request.Method,
			request.Header.Get("Accept-Encoding"), request.Header.Get("Authorization")}
		_, _ = io.WriteString(writer, "ip=203.0.113.8\nloc=SG\n")
	})

	got := fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL+"/cdn-cgi/trace", 5000, "Clash/1.0 test"))
	wantFetched(t, got, http.StatusOK, "ip=203.0.113.8\nloc=SG\n", "新加坡 01")
	request := <-requests
	if request.userAgent != "Clash/1.0 test" || request.cookie != "" || request.connection != "close" || request.method != http.MethodGet ||
		request.encoding != "" || request.authorization != "" {
		t.Fatalf("the origin saw %+v; want the App's User-Agent and nothing else of anybody's: no cookie, no Accept-Encoding, no Authorization, Connection close, GET", request)
	}
	if asked := proxy.asked(); fmt.Sprint(asked) != fmt.Sprint([]string{strings.TrimPrefix(origin.URL, "https://")}) {
		t.Fatalf("the node was asked for %v, want the origin once", asked)
	}
	node, _ := tunnel.LookupProxy("新加坡 01")
	if history := node.DelayHistory(); len(history) != 0 {
		t.Fatalf("a lookup wrote the node's delay history: %v", history)
	}
}

func TestFetchThroughSendsTheCoresUserAgentWhenTheAppGivesNone(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	agents := make(chan string, 1)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		agents <- request.Header.Get("User-Agent")
	})
	got := fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL, 5000, ""))
	wantFetched(t, got, http.StatusOK, "", "新加坡 01")
	if agent := <-agents; agent == "" || strings.HasPrefix(agent, "Go-http-client") {
		t.Fatalf("the origin saw User-Agent %q, want the core's", agent)
	}
}

func TestFetchThroughDialsAGroupThroughItsChoice(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "group")
	})
	got := fetchThrough(t, client, fetchThroughJSON(t, "节点选择", origin.URL, 5000, ""))
	wantFetched(t, got, http.StatusOK, "group", "新加坡 01", "节点选择")
	if len(proxy.asked()) != 1 {
		t.Fatalf("the group's node was asked %v times, want once", proxy.asked())
	}
}

func TestFetchThroughReachesTheOriginOverDIRECT(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "direct")
	})
	got := fetchThrough(t, client, fetchThroughJSON(t, "DIRECT", origin.URL, 5000, ""))
	wantFetched(t, got, http.StatusOK, "direct", "DIRECT")
	if asked := proxy.asked(); len(asked) != 0 {
		t.Fatalf("a DIRECT lookup went through the node: %v", asked)
	}
}

func TestFetchThroughSaysWhatItCouldNotReach(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	reached := make(chan struct{}, 8)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		reached <- struct{}{}
	})
	notTLS, _ := rawOrigin(t, func(connection net.Conn) {
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno")
	})

	for _, c := range []struct {
		name, proxy, url, failure string
	}{
		{"a name the configuration does not have", "香港 99", origin.URL, "notFound"},
		{"REJECT", "REJECT", origin.URL, "refused"},
		{"REJECT-DROP", "REJECT-DROP", origin.URL, "refused"},
		{"a group that selects REJECT", "拒绝组", origin.URL, "refused"},
		{"PASS-RULE", "PASS-RULE", origin.URL, "refused"},
		{"a dns outbound", "dns-out", origin.URL, "refused"},
		{"a rematch outbound", "again", origin.URL, "refused"},
		{"a node that cannot be reached", "dead", origin.URL, "dialFailed"},
		{"an origin that does not speak TLS", "新加坡 01", "https://" + notTLS, "requestFailed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantFailure(t, fetchThrough(t, client, fetchThroughJSON(t, c.proxy, c.url, 3000, "")), c.failure)
		})
	}
	select {
	case <-reached:
		t.Fatal("a lookup that failed reached the origin")
	default:
	}
}

func TestFetchThroughRefusesABodyOverEightKilobytes(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		size := 8 << 10
		switch request.URL.Path {
		case "/over":
			size++
		case "/chunked":
			size += 1000
			writer.(http.Flusher).Flush()
		}
		_, _ = io.WriteString(writer, strings.Repeat("a", size))
	})
	wantFetched(t, fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL+"/limit", 5000, "")),
		http.StatusOK, strings.Repeat("a", 8<<10), "新加坡 01")
	for _, path := range []string{"/over", "/chunked"} {
		got := fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL+path, 5000, ""))
		wantFailure(t, got, "tooLarge")
		if fmt.Sprint(got.Chain) != "[新加坡 01]" {
			t.Fatalf("%s: a failure after the dial names no chain: %v", path, got.Chain)
		}
	}
}

func TestFetchThroughTimesOutOnItsOwnClockAndClosesTheOrigin(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	released := make(chan time.Time, 1)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "100")
		_, _ = writer.Write([]byte("z"))
		writer.(http.Flusher).Flush()
		select {
		case <-request.Context().Done():
			released <- time.Now()
		case <-time.After(30 * time.Second):
		}
	})
	start := time.Now()
	got := fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL, 1000, ""))
	answered := time.Now()
	wantFailure(t, got, "timeout")
	if took := answered.Sub(start); took < time.Second || took > 2500*time.Millisecond {
		t.Fatalf("a 1 s lookup answered after %s", took)
	}
	select {
	case at := <-released:
		if at.Sub(answered) > directFetchClosePromptly {
			t.Fatalf("the origin was released %s after the App had its answer", at.Sub(answered))
		}
	case <-time.After(directFetchClosePromptly):
		t.Fatal("the origin's connection was still open after the lookup timed out")
	}
}

func TestFetchThroughAnswersARedirectAsItStands(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	followed := make(chan struct{}, 1)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/moved" {
			followed <- struct{}{}
			return
		}
		http.Redirect(writer, request, "/moved", http.StatusFound)
	})
	got := fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL+"/geoip", 5000, ""))
	if got.Failure != "" || got.Status == nil || *got.Status != http.StatusFound {
		t.Fatalf("answer = %+v, want the 302 as it stands", got)
	}
	select {
	case <-followed:
		t.Fatal("the lookup followed the redirect")
	default:
	}
}

func TestFetchThroughReplacesBytesThatAreNotUTF8(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("\xff203.0.113.8"))
	})
	wantFetched(t, fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL, 5000, "")),
		http.StatusOK, "�203.0.113.8", "新加坡 01")
}

func TestFetchThroughRefusesWhatIsNotALookup(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	reached := make(chan struct{}, 16)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		reached <- struct{}{}
	})
	plain := "http://" + strings.TrimPrefix(origin.URL, "https://")
	requests := map[string]string{
		"plain http":                  fetchThroughJSON(t, "新加坡 01", plain, 5000, ""),
		"another scheme":              fetchThroughJSON(t, "新加坡 01", "ftp://203.0.113.8/", 5000, ""),
		"no host":                     fetchThroughJSON(t, "新加坡 01", "https:///geoip", 5000, ""),
		"a timeout under 1 s":         fetchThroughJSON(t, "新加坡 01", origin.URL, 999, ""),
		"a timeout over 10 s":         fetchThroughJSON(t, "新加坡 01", origin.URL, 10_001, ""),
		"no outbound":                 fetchThroughJSON(t, "", origin.URL, 5000, ""),
		"a User-Agent with a CR":      fetchThroughJSON(t, "新加坡 01", origin.URL, 5000, "a\r\nCookie: x"),
		"a request that is not JSON":  `{"proxy":`,
		"credentials in the URL":      fetchThroughJSON(t, "新加坡 01", "https://u:p@"+strings.TrimPrefix(origin.URL, "https://"), 5000, ""),
		"a port over 65535":           fetchThroughJSON(t, "新加坡 01", "https://127.0.0.1:99999/", 5000, ""),
		"port 0":                      fetchThroughJSON(t, "新加坡 01", "https://127.0.0.1:0/", 5000, ""),
		"a URL over 4 KiB":            fetchThroughJSON(t, "新加坡 01", origin.URL+"/?"+strings.Repeat("q", 4<<10), 5000, ""),
		"an outbound name over 1 KiB": fetchThroughJSON(t, strings.Repeat("n", 1025), origin.URL, 5000, ""),
	}
	for name, request := range requests {
		t.Run("App/"+name, func(t *testing.T) {
			wantFailure(t, fetchThrough(t, client, request), "invalidRequest")
		})
		t.Run("route/"+name, func(t *testing.T) {
			response, body := postFetchThroughRoute(t, client, request)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("the route answered %d (%s), want 200 with the failure", response.StatusCode, body)
			}
			wantFailure(t, decodeFetchThrough(t, string(body)), "invalidRequest")
		})
	}
	select {
	case <-reached:
		t.Fatal("a request that is not a lookup reached the origin")
	default:
	}
	if asked := proxy.asked(); len(asked) != 0 {
		t.Fatalf("a request that is not a lookup was dialed: %v", asked)
	}
}

func postFetchThroughRoute(t *testing.T, client *APIClient, body string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://localhost"+privateAPIPrefix+fetchThroughRoute, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	received, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, received
}

func TestFetchThroughRouteAnswersOnlyOnTheAppGroupSocket(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "inside")
	})
	serve := func(network, address string) string {
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		server := &mhttp.Server{Handler: mhttp.HandlerFunc(serveFetchThrough)}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })
		return listener.Addr().String()
	}
	body := fetchThroughJSON(t, "新加坡 01", origin.URL, 5000, "")

	tcp := serve("tcp", "127.0.0.1:0")
	response, err := http.Post("http://"+tcp+privateAPIPrefix+fetchThroughRoute, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("over TCP the route answered %d, want 404", response.StatusCode)
	}
	if asked := proxy.asked(); len(asked) != 0 {
		t.Fatalf("the route dialed for a TCP caller: %v", asked)
	}

	unix := serve("unix", shortClashSocketPath(t))
	client, err := NewAPIClient(unix, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	wantFetched(t, fetchThrough(t, client, body), http.StatusOK, "inside", "新加坡 01")
}

func TestFetchThroughSaysUnavailableWithoutARunningCoreOrTheRoute(t *testing.T) {
	if currentCoreService() != nil {
		t.Fatal("a core from another test is still published")
	}
	request := fetchThroughJSON(t, "DIRECT", "https://203.0.113.8/", 2000, "")
	for name, client := range map[string]*APIClient{
		"no core":           directFetchClientOnControlPlane(t),
		"without the route": directFetchClientOn(t, http.NotFoundHandler()),
	} {
		if _, err := client.FetchThrough(request); err == nil || !strings.HasPrefix(err.Error(), FetchThroughUnavailablePrefix) {
			t.Fatalf("%s: err = %v, want the unavailable prefix", name, err)
		}
	}
	gone, err := NewAPIClient(shortClashSocketPath(t), newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gone.FetchThrough(request); err == nil || !strings.HasPrefix(err.Error(), FetchThroughUnavailablePrefix) {
		t.Fatalf("no Extension: err = %v, want the unavailable prefix", err)
	}
}

func keptTLSOrigin(t *testing.T, body string) string {
	t.Helper()
	return fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, body)
	}).URL
}

func lookupRequest(proxy, url string, timeout time.Duration) fetchThroughRequest {
	return fetchThroughRequest{Proxy: proxy, URL: url, TimeoutMilliseconds: timeout.Milliseconds()}
}

func TestALookupReleasesTheSessionItOpened(t *testing.T) {
	armedSessionRelease(t)
	node, resets := keepingNode("quic")
	restore := swapTunnelProxies(map[string]C.Proxy{"quic": node}, map[string]P.ProxyProvider{})
	defer restore()
	url := keptTLSOrigin(t, "203.0.113.9")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := runFetchThrough(ctx, lookupRequest("quic", url, 5*time.Second))
	if got.Failure != "" || got.Body == nil || *got.Body != "203.0.113.9" {
		t.Fatalf("lookup = %+v", got)
	}
	if n := resets.Load(); n != 1 {
		t.Fatalf("the node's session was dropped %d times after the lookup, want once", n)
	}
}

func TestALookupLeavesTheSessionOfANodeInUse(t *testing.T) {
	armedSessionRelease(t)
	node, resets := keepingNode("in-use")
	restore := swapTunnelProxies(map[string]C.Proxy{"in-use": node}, map[string]P.ProxyProvider{})
	defer restore()
	url := keptTLSOrigin(t, "203.0.113.10")
	held, err := node.DialContext(dialer.WithDialKind(context.Background(), dialer.DialKindProbe), serverTarget(t, strings.Replace(url, "https://", "http://", 1)))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := runFetchThrough(ctx, lookupRequest("in-use", url, 5*time.Second)); got.Failure != "" {
		t.Fatalf("lookup = %+v", got)
	}
	if n := resets.Load(); n != 0 {
		t.Fatalf("a lookup dropped the session of a node in use (%d)", n)
	}
}

func TestALookupTakesAnInteractiveProbeSlotAndItsClockRunsInTheQueue(t *testing.T) {
	adapter.SetURLTestGate(newProbeAdmissionHook(probeAdmissionConfig{interactiveCap: 1, backgroundCap: func() int { return 1 }}))
	t.Cleanup(func() { adapter.SetURLTestGate(nil) })
	counts := func() (int, int, int, int) { return (*probeAdmissionCounts.Load())() }

	holding, _ := keepingNode("holding")
	waiting, _ := keepingNode("waiting")
	restore := swapTunnelProxies(map[string]C.Proxy{"holding": holding, "waiting": waiting}, map[string]P.ProxyProvider{})
	defer restore()
	release := make(chan struct{})
	held := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-release:
		case <-request.Context().Done():
		}
	})
	reached := make(chan struct{}, 1)
	other := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		reached <- struct{}{}
	})

	first := make(chan fetchThroughAnswer, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		first <- runFetchThrough(ctx, lookupRequest("holding", held.URL, 10*time.Second))
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		interactive, background, _, _ := counts()
		if interactive == 1 && background == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lookup in flight holds %d interactive and %d background slots, want one interactive", interactive, background)
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	got := runFetchThrough(ctx, lookupRequest("waiting", other.URL, time.Second))
	if got.Failure != "timeout" {
		t.Fatalf("a lookup that waited out its time in the queue = %+v, want timeout", got)
	}
	if took := time.Since(start); took < 900*time.Millisecond || took > 2*time.Second {
		t.Fatalf("the queued lookup answered after %s, want its 1 s", took)
	}
	select {
	case <-reached:
		t.Fatal("a lookup that never had a slot reached its origin")
	default:
	}

	close(release)
	if answer := <-first; answer.Failure != "" {
		t.Fatalf("the lookup that held the slot = %+v", answer)
	}
	if interactive, _, waitingCount, _ := counts(); interactive != 0 || waitingCount != 0 {
		t.Fatalf("after both lookups the gate holds %d in flight and %d waiting", interactive, waitingCount)
	}
}

func TestFetchThroughAnswersOnTimeWhenADialIgnoresItsDeadline(t *testing.T) {
	release := make(chan struct{})
	late := &atomic.Bool{}
	node := adapter.NewProxy(stallingDial{
		Direct:  outbound.NewDirectWithOption(outbound.DirectOption{Name: "stalling"}),
		release: release,
		closed:  late,
	})
	restore := swapTunnelProxies(map[string]C.Proxy{"stalling": node}, map[string]P.ProxyProvider{})
	defer restore()
	timer := time.AfterFunc(3*time.Second, func() { close(release) })
	defer timer.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	got := runFetchThrough(ctx, lookupRequest("stalling", "https://203.0.113.8/", time.Second))
	if got.Failure != "timeout" {
		t.Fatalf("lookup through a dial that ignores its deadline = %+v, want timeout", got)
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("the lookup answered after %s, past its 1 s", took)
	}
	deadline := time.Now().Add(4 * time.Second)
	for !late.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the connection the dial brought back late was left open")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type stallingDial struct {
	*outbound.Direct
	release chan struct{}
	closed  *atomic.Bool
	resets  *atomic.Int64
}

func (s stallingDial) ResetNetwork() {
	if s.resets != nil {
		s.resets.Add(1)
	}
}

func (s stallingDial) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	<-s.release
	client, server := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	return outbound.NewConn(closeRecorder{Conn: client, closed: s.closed}, s), nil
}

type closeRecorder struct {
	net.Conn
	closed *atomic.Bool
}

func (c closeRecorder) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestALookupThatTimesOutReleasesItsSessionAndItsSlot(t *testing.T) {
	armedSessionRelease(t)
	adapter.SetURLTestGate(newProbeAdmissionHook(probeAdmissionConfig{interactiveCap: 1, backgroundCap: func() int { return 1 }}))
	t.Cleanup(func() { adapter.SetURLTestGate(nil) })
	node, resets := keepingNode("slow")
	restore := swapTunnelProxies(map[string]C.Proxy{"slow": node}, map[string]P.ProxyProvider{})
	defer restore()
	held := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "100")
		_, _ = writer.Write([]byte("z"))
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := runFetchThrough(ctx, lookupRequest("slow", held.URL, time.Second)); got.Failure != "timeout" {
		t.Fatalf("lookup = %+v, want timeout", got)
	}
	deadline := time.Now().Add(time.Second)
	for {
		interactive, background, waiting, _ := (*probeAdmissionCounts.Load())()
		if resets.Load() == 1 && interactive == 0 && background == 0 && waiting == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a second after a lookup that timed out: the session dropped %d times (want once), the gate holds %d interactive, %d background, %d waiting",
				resets.Load(), interactive, background, waiting)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFetchThroughRefusesAnswerHeadersOverTheirBound(t *testing.T) {
	proxy := newConnectProxy(t)
	startDirectFetchCore(t, fetchThroughYAML(proxy))
	client := directFetchClientOnControlPlane(t)
	origin := fetchThroughOrigin(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Padding", strings.Repeat("p", 64<<10))
		_, _ = io.WriteString(writer, "203.0.113.8")
	})
	wantFailure(t, fetchThrough(t, client, fetchThroughJSON(t, "新加坡 01", origin.URL, 5000, "")), "requestFailed")
}

func TestALookupWhoseDialIgnoresItsDeadlineKeepsItsSlotAndReleasesItsSessionWhenTheDialEnds(t *testing.T) {
	armedSessionRelease(t)
	adapter.SetURLTestGate(newProbeAdmissionHook(probeAdmissionConfig{interactiveCap: 1, backgroundCap: func() int { return 1 }}))
	t.Cleanup(func() { adapter.SetURLTestGate(nil) })
	counts := func() (int, int, int, int) { return (*probeAdmissionCounts.Load())() }
	release := make(chan struct{})
	resets := &atomic.Int64{}
	node := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(stallingDial{
		Direct:  outbound.NewDirectWithOption(outbound.DirectOption{Name: "stalling-quic"}),
		release: release,
		closed:  &atomic.Bool{},
		resets:  resets,
	}))
	restore := swapTunnelProxies(map[string]C.Proxy{"stalling-quic": node}, map[string]P.ProxyProvider{})
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if got := runFetchThrough(ctx, lookupRequest("stalling-quic", "https://203.0.113.8/", time.Second)); got.Failure != "timeout" {
		t.Fatalf("lookup = %+v, want timeout", got)
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("the lookup answered after %s, past its 1 s", took)
	}
	if interactive, _, _, _ := counts(); interactive != 1 {
		t.Fatalf("with its dial still running the lookup holds %d interactive slots, want its one", interactive)
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		interactive, _, _, _ := counts()
		if interactive == 0 && resets.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the dial ended: %d interactive slots held, the session dropped %d times; want 0 and once", interactive, resets.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestALookupWhoseDialPanicsIsAFailure(t *testing.T) {
	armedSessionRelease(t)
	adapter.SetURLTestGate(newProbeAdmissionHook(probeAdmissionConfig{interactiveCap: 1, backgroundCap: func() int { return 1 }}))
	t.Cleanup(func() { adapter.SetURLTestGate(nil) })
	resets := &atomic.Int64{}
	node := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(panickingDial{
		Direct: outbound.NewDirectWithOption(outbound.DirectOption{Name: "panicking"}),
		resets: resets,
	}))
	restore := swapTunnelProxies(map[string]C.Proxy{"panicking": node}, map[string]P.ProxyProvider{})
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := runFetchThrough(ctx, lookupRequest("panicking", "https://203.0.113.8/", 2*time.Second))
	if got.Failure != "requestFailed" || !strings.Contains(got.Message, "a dial that panics") || !strings.Contains(got.Message, "goroutine ") {
		t.Fatalf("lookup through a dial that panics = %+v, want requestFailed with the panic and its stack", got)
	}
	if n := resets.Load(); n != 1 {
		t.Fatalf("the panicking node's session was dropped %d times, want once", n)
	}
	if interactive, background, waiting, _ := (*probeAdmissionCounts.Load())(); interactive != 0 || background != 0 || waiting != 0 {
		t.Fatalf("after a panicking lookup the gate holds %d interactive, %d background, %d waiting", interactive, background, waiting)
	}
}

type panickingDial struct {
	*outbound.Direct
	resets *atomic.Int64
}

func (panickingDial) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	panic("a dial that panics")
}

func (p panickingDial) ResetNetwork() { p.resets.Add(1) }

func TestFetchThroughRefusesARequestThatWritesPastTheExtensionsRead(t *testing.T) {
	client := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Error("a request too large to read was sent")
	}))
	got := fetchThrough(t, client, fetchThroughJSON(t, strings.Repeat("<", 1000), "https://203.0.113.8/?"+strings.Repeat("<", 4000), 5000, ""))
	wantFailure(t, got, "invalidRequest")
	if !strings.Contains(got.Message, "bytes") {
		t.Fatalf("the refusal says %q; want it to name the request's size", got.Message)
	}
}

func TestFetchThroughRefusesADialThatWentToREJECT(t *testing.T) {
	shown, _ := keepingNode("shown")
	reject := adapter.NewProxy(outbound.NewReject())
	group := adapter.NewProxy(switchingGroup{Direct: outbound.NewDirectWithOption(outbound.DirectOption{Name: "switching"}), shown: shown, dials: reject})
	restore := swapTunnelProxies(map[string]C.Proxy{"switching": group, "shown": shown, "REJECT": reject}, map[string]P.ProxyProvider{})
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := runFetchThrough(ctx, lookupRequest("switching", "https://203.0.113.8/", 2*time.Second))
	if got.Failure != "refused" || fmt.Sprint(got.Chain) != "[REJECT switching]" {
		t.Fatalf("lookup = %+v, want refused with the chain the dial went", got)
	}
}

type switchingGroup struct {
	*outbound.Direct
	shown, dials C.Proxy
}

func (switchingGroup) Type() C.AdapterType                { return C.Selector }
func (g switchingGroup) Unwrap(*C.Metadata, bool) C.Proxy { return g.shown }
func (g switchingGroup) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	connection, err := g.dials.DialContext(ctx, metadata)
	if err == nil {
		connection.AppendToChains(g)
	}
	return connection, err
}

func TestFetchThroughTakesASubscriptionsNodeNamedREJECTForTheNode(t *testing.T) {
	resets := &atomic.Int64{}
	direct := outbound.NewDirectWithOption(outbound.DirectOption{BasicOption: outbound.BasicOption{ProviderName: "sub"}, Name: "REJECT"})
	node := adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(keepingDirect{Direct: direct, resets: resets}))
	members, err := provider.NewCompatibleProvider("sub", []C.Proxy{node}, provider.NewHealthCheck([]C.Proxy{node}, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	selector, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: "节点组"}, outboundgroup.SelectorOption{}, node, []P.ProxyProvider{members})
	if err != nil {
		t.Fatal(err)
	}
	group := adapter.NewProxy(selector)
	restore := swapTunnelProxies(map[string]C.Proxy{"节点组": group, "REJECT": adapter.NewProxy(outbound.NewReject())}, map[string]P.ProxyProvider{"sub": members})
	defer restore()
	url := keptTLSOrigin(t, "203.0.113.11")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := runFetchThrough(ctx, lookupRequest("节点组", url, 5*time.Second))
	if got.Failure != "" || got.Body == nil || *got.Body != "203.0.113.11" {
		t.Fatalf("lookup through a subscription's node named REJECT = %+v, want its answer", got)
	}
}
