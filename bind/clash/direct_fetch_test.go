package clash

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	mihomoHttp "github.com/ProjectClash/Clash/component/http"
	mhttp "github.com/metacubex/http"
)

const rejectEverythingYAML = `
mode: rule
log-level: info
proxies:
  - name: probe
    type: socks5
    server: 127.0.0.1
    port: 1
rules:
  - MATCH,REJECT
`

const directFetchClosePromptly = time.Second

func startDirectFetchCore(t *testing.T, configuration string) (*BoxService, *APIClient) {
	t.Helper()
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(configuration); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return service, directFetchClientOnControlPlane(t)
}

func directFetchClientOnControlPlane(t *testing.T) *APIClient {
	t.Helper()
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func directFetchClientOn(t *testing.T, handler http.Handler) *APIClient {
	t.Helper()
	path := shortClashSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	client, err := NewAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func directFetchRequestJSON(t *testing.T, url string, headers map[string][]string, timeoutMilliseconds, maximumBytes int64) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"url":                 url,
		"headers":             headers,
		"timeoutMilliseconds": timeoutMilliseconds,
		"maximumBytes":        maximumBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func decodeDirectFetchAnswer(t *testing.T, answer string) directFetchAnswer {
	t.Helper()
	var decoded directFetchAnswer
	if err := json.Unmarshal([]byte(answer), &decoded); err != nil {
		t.Fatalf("answer %q is not JSON: %v", answer, err)
	}
	return decoded
}

func postDirectFetchRoute(t *testing.T, ctx context.Context, client *APIClient, body string) (*http.Response, []byte, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+privateAPIPrefix+directFetchRoute, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	received, err := io.ReadAll(response.Body)
	return response, received, err
}

func directoryHolds(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	if fmt.Sprint(got) != fmt.Sprint(append([]string(nil), names...)) {
		t.Fatalf("%s holds %v, want %v", dir, got, names)
	}
}

type heldOrigin struct {
	*httptest.Server
	closedByCore atomic.Bool
	released     chan struct{}
}

func newHeldOrigin(t *testing.T) *heldOrigin {
	t.Helper()
	origin := &heldOrigin{released: make(chan struct{})}
	origin.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "100000")
		_, _ = writer.Write([]byte("z"))
		writer.(http.Flusher).Flush()
		select {
		case <-request.Context().Done():
			origin.closedByCore.Store(true)
		case <-time.After(30 * time.Second):
		}
		close(origin.released)
	}))
	t.Cleanup(origin.Close)
	return origin
}

func (o *heldOrigin) wantReleasedByCore(t *testing.T, since time.Time) {
	t.Helper()
	select {
	case <-o.released:
	case <-time.After(directFetchClosePromptly):
		t.Fatalf("the origin's connection was still open %s after the App had its answer", directFetchClosePromptly)
	}
	if !o.closedByCore.Load() {
		t.Fatal("the origin was released by its own timer, not by the core closing the download")
	}
	if waited := time.Since(since); waited > directFetchClosePromptly {
		t.Fatalf("the origin was released %s after the App had its answer", waited)
	}
}

func rawOrigin(t *testing.T, serve func(net.Conn)) (string, <-chan time.Time) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	closed := make(chan time.Time, 4)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				serve(connection)
				_, _ = io.Copy(io.Discard, connection)
				closed <- time.Now()
			}()
		}
	}()
	return listener.Addr().String(), closed
}

func TestFetchDirectReachesTheOriginOverDIRECTWhileEveryRuleRejects(t *testing.T) {
	const body = "proxies:\n  - {name: a, type: socks5, server: 192.0.2.1, port: 1}\n"
	type seen struct {
		userAgent, ifNoneMatch, connection string
	}
	requests := make(chan seen, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- seen{request.Header.Get("User-Agent"), request.Header.Get("If-None-Match"), request.Header.Get("Connection")}
		writer.Header().Set("ETag", `"v2"`)
		writer.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
		writer.Header().Set("Profile-Update-Interval", "24")
		writer.Header().Set("Content-Disposition", `attachment; filename="sub.yaml"`)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(origin.Close)

	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	control, err := mihomoHttp.HttpRequest(context.Background(), origin.URL, http.MethodGet, nil, nil)
	if err == nil {
		_ = control.Body.Close()
		t.Fatal("control: a request left to the rules reached the origin; MATCH,REJECT is not rejecting, so this test proves nothing")
	}

	destination := filepath.Join(t.TempDir(), "subscription.yaml")
	answer, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL+"/sub?token=t0k3n",
		map[string][]string{"User-Agent": {"clash.meta"}, "If-None-Match": {`"v1"`}}, 10_000, 1<<20), destination)
	if err != nil {
		t.Fatalf("FetchDirect: %v", err)
	}
	got := <-requests
	if got.userAgent != "clash.meta" || got.ifNoneMatch != `"v1"` {
		t.Fatalf("the origin saw User-Agent %q and If-None-Match %q; the App's headers were not sent", got.userAgent, got.ifNoneMatch)
	}
	if got.connection != "close" {
		t.Fatalf("the origin saw Connection %q; the download is one request and says so", got.connection)
	}
	decoded := decodeDirectFetchAnswer(t, answer)
	if decoded.Status != http.StatusOK || decoded.Bytes != int64(len(body)) {
		t.Fatalf("answer = %+v, want status 200 and %d bytes", decoded, len(body))
	}
	for name, want := range map[string]string{
		"etag":                    `"v2"`,
		"subscription-userinfo":   "upload=1; download=2; total=3; expire=4",
		"profile-update-interval": "24",
		"content-disposition":     `attachment; filename="sub.yaml"`,
	} {
		if value := http.Header(decoded.Headers).Get(name); value != want {
			t.Errorf("header %s = %q, want %q (answer %s)", name, value, want, answer)
		}
	}
	written, err := os.ReadFile(destination)
	if err != nil || string(written) != body {
		t.Fatalf("destination holds %q (%v), want the body", written, err)
	}
	directoryHolds(t, filepath.Dir(destination), "subscription.yaml")
}

func TestFetchDirectWritesADestinationWithTheLongestName(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "long")
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	name := strings.Repeat("n", 255)
	destination := filepath.Join(t.TempDir(), name)
	if _, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), destination); err != nil {
		t.Fatalf("FetchDirect to a 255-byte name: %v", err)
	}
	if written, err := os.ReadFile(destination); err != nil || string(written) != "long" {
		t.Fatalf("destination holds %q (%v)", written, err)
	}
	directoryHolds(t, filepath.Dir(destination), name)
}

func TestFetchDirectAnswersNotModifiedWithAnEmptyFile(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("ETag", `"v1"`)
		writer.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "rules.mrs")
	answer, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, map[string][]string{"If-None-Match": {`"v1"`}}, 10_000, 1<<20), destination)
	if err != nil {
		t.Fatalf("FetchDirect: %v", err)
	}
	if decoded := decodeDirectFetchAnswer(t, answer); decoded.Status != http.StatusNotModified || decoded.Bytes != 0 {
		t.Fatalf("answer = %+v, want 304 with no bytes", decoded)
	}
	if info, err := os.Stat(destination); err != nil || info.Size() != 0 {
		t.Fatalf("destination after a 304: %v, %v; want an empty file", info, err)
	}
}

func TestFetchDirectWritesTheDecodedBodyWhateverTheAppAskedFor(t *testing.T) {
	const body = "payload:\n  - DOMAIN-SUFFIX,example.com\n"
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") || strings.Contains(request.Header.Get("Accept-Encoding"), "br") {
			http.Error(writer, "Accept-Encoding "+request.Header.Get("Accept-Encoding"), http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Encoding", "gzip")
		compressor := gzip.NewWriter(writer)
		_, _ = compressor.Write([]byte(body))
		_ = compressor.Close()
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "rules.yaml")
	answer, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL,
		map[string][]string{"Accept-Encoding": {"br, gzip"}}, 10_000, 1<<20), destination)
	if err != nil {
		t.Fatalf("FetchDirect: %v", err)
	}
	decoded := decodeDirectFetchAnswer(t, answer)
	if decoded.Status != http.StatusOK || http.Header(decoded.Headers).Get("Content-Encoding") != "" {
		t.Fatalf("answer = %s, want 200 with no Content-Encoding", answer)
	}
	if written, err := os.ReadFile(destination); err != nil || string(written) != body {
		t.Fatalf("destination holds %q (%v), want the decoded body", written, err)
	}
}

func TestFetchDirectRefusesABodyOverItsLimitAndLeavesNoFile(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 4096)))
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "big.yaml")
	_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), destination)
	if err == nil || !strings.Contains(err.Error(), "1024") {
		t.Fatalf("FetchDirect over the limit: err = %v, want a failure naming the limit", err)
	}
	if strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("a body over the limit reads as interrupted: %v", err)
	}
	directoryHolds(t, filepath.Dir(destination))
}

func TestDirectFetchRouteHoldsTheLimitItself(t *testing.T) {
	declared := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "4096")
		_, _ = writer.Write([]byte(strings.Repeat("x", 4096)))
	}))
	t.Cleanup(declared.Close)
	undeclared := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.(http.Flusher).Flush()
		_, _ = writer.Write([]byte(strings.Repeat("x", 4096)))
	}))
	t.Cleanup(undeclared.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	response, received, err := postDirectFetchRoute(t, context.Background(), client, directFetchRequestJSON(t, declared.URL, nil, 10_000, 1024))
	if err != nil {
		t.Fatal(err)
	}
	if result := response.Trailer.Get(directFetchResultTrailer); !strings.Contains(result, "1024") || !strings.Contains(result, "4096") {
		t.Fatalf("the core's last word on a declared 4096 against 1024 is %q, want both named", result)
	}
	if len(received) != 0 {
		t.Fatalf("the core passed on %d bytes of a body it knew was over the limit", len(received))
	}

	response, _, err = postDirectFetchRoute(t, context.Background(), client, directFetchRequestJSON(t, undeclared.URL, nil, 10_000, 1024))
	if err != nil {
		t.Fatal(err)
	}
	if result := response.Trailer.Get(directFetchResultTrailer); !strings.Contains(result, "1024") {
		t.Fatalf("the core's last word on an undeclared body over the limit is %q, want one naming the limit", result)
	}
}

func TestFetchDirectHoldsTheLimitAgainstAnAnswerThatSaysComplete(t *testing.T) {
	client := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(directFetchAnswerHeader, `{"status":200,"headers":{}}`)
		writer.Header().Set("Trailer", directFetchResultTrailer)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(strings.Repeat("x", 2048)))
		writer.Header().Set(directFetchResultTrailer, directFetchComplete)
	}))
	destination := filepath.Join(t.TempDir(), "over")
	_, err := client.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 5000, 1024), destination)
	if err == nil || !strings.Contains(err.Error(), "1024") {
		t.Fatalf("FetchDirect of 2048 bytes against a 1024 limit: err = %v", err)
	}
	directoryHolds(t, filepath.Dir(destination))
}

func TestFetchDirectReportsAnOriginThatBreaksOffMidBody(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "100000")
		_, _ = writer.Write([]byte(strings.Repeat("y", 1000)))
		writer.(http.Flusher).Flush()
		connection, _, _ := writer.(http.Hijacker).Hijack()
		_ = connection.Close()
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "subscription.yaml")
	if err := os.WriteFile(destination, []byte("the last good copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL+"/cut", nil, 10_000, 1<<20), destination)
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) ||
		!strings.Contains(err.Error(), "EOF") || !strings.Contains(err.Error(), origin.URL+"/cut") {
		t.Fatalf("FetchDirect of a cut body: err = %v, want the interrupted prefix, the core's EOF and the URL", err)
	}
	if kept, err := os.ReadFile(destination); err != nil || string(kept) != "the last good copy" {
		t.Fatalf("after a cut body the destination holds %q (%v), want what was there", kept, err)
	}
	directoryHolds(t, filepath.Dir(destination), "subscription.yaml")
}

func TestFetchDirectReportsAFailedRequestInTheCoresWords(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	url := "http://" + address + "/sub"
	_, err = client.FetchDirect(directFetchRequestJSON(t, url, nil, 1000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || strings.HasPrefix(err.Error(), DirectFetchUnavailablePrefix) {
		t.Fatalf("FetchDirect to a closed port: err = %v, want the download's own failure", err)
	}
	if n := strings.Count(err.Error(), url); n != 1 {
		t.Fatalf("the error names the URL %d times: %v", n, err)
	}
}

func TestFetchDirectLeavesTheDestinationOfADirectoryItCannotWrite(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("new"))
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "kept")
	if err := os.WriteFile(destination, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), destination); err == nil {
		t.Fatal("FetchDirect succeeded into a directory it cannot write")
	}
	if kept, err := os.ReadFile(destination); err != nil || string(kept) != "kept" {
		t.Fatalf("the destination now holds %q (%v); a failed download touched what the App had", kept, err)
	}
	directoryHolds(t, dir, "kept")
}

func TestFetchDirectTimesOutOnTheCoresClockAndStopsThere(t *testing.T) {
	origin := newHeldOrigin(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	started := time.Now()
	_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 1000, 1<<20), filepath.Join(t.TempDir(), "slow"))
	answered := time.Now()
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("FetchDirect past its timeout: err = %v, want the core's deadline", err)
	}
	if strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("a timeout reads as interrupted: %v; trying again would only wait as long again", err)
	}
	if elapsed := answered.Sub(started); elapsed > 1000*time.Millisecond+directFetchAnswerGrace {
		t.Fatalf("FetchDirect took %s, past its timeout plus the grace", elapsed)
	}
	origin.wantReleasedByCore(t, answered)
}

func TestFetchDirectClosesAStalledHandshakeWhenItGivesUp(t *testing.T) {
	address, closed := rawOrigin(t, func(net.Conn) {})
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	_, err := client.FetchDirect(directFetchRequestJSON(t, "https://"+address+"/sub", nil, 1000, 1024), filepath.Join(t.TempDir(), "a"))
	answered := time.Now()
	if err == nil {
		t.Fatal("FetchDirect succeeded against an origin that never answered")
	}
	select {
	case at := <-closed:
		if waited := at.Sub(answered); waited > directFetchClosePromptly {
			t.Fatalf("the stalled handshake was closed %s after the App had its answer", waited)
		}
	case <-time.After(directFetchClosePromptly):
		t.Fatalf("the stalled handshake was still open %s after the App had its answer", directFetchClosePromptly)
	}
}

func TestFetchDirectClosesAnOriginThatKeepsTheConnection(t *testing.T) {
	address, closed := rawOrigin(t, func(connection net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
	})
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "a")
	if _, err := client.FetchDirect(directFetchRequestJSON(t, "http://"+address+"/sub", nil, 10_000, 1024), destination); err != nil {
		t.Fatalf("FetchDirect: %v", err)
	}
	answered := time.Now()
	select {
	case at := <-closed:
		if waited := at.Sub(answered); waited > directFetchClosePromptly {
			t.Fatalf("the finished connection was closed %s after the App had its answer", waited)
		}
	case <-time.After(directFetchClosePromptly):
		t.Fatalf("the finished connection was still open %s after the App had its answer", directFetchClosePromptly)
	}
}

func TestDirectFetchStopsWhenTheAppGoesAway(t *testing.T) {
	origin := newHeldOrigin(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, _, err := postDirectFetchRoute(t, ctx, client, directFetchRequestJSON(t, origin.URL, nil, 60_000, 1<<20)); err == nil {
		t.Fatal("the abandoned request completed")
	}
	origin.wantReleasedByCore(t, time.Now())
}

func TestFetchDirectEndsWhenTheCoreStops(t *testing.T) {
	origin := newHeldOrigin(t)
	service, client := startDirectFetchCore(t, rejectEverythingYAML)

	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = service.Close()
	}()
	destination := filepath.Join(t.TempDir(), "a")
	if _, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 60_000, 1<<20), destination); err == nil {
		t.Fatal("FetchDirect succeeded across the core stopping")
	} else if !strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("a download cut by the core stopping: err = %v, want the interrupted prefix", err)
	}
	origin.wantReleasedByCore(t, time.Now())
	directoryHolds(t, filepath.Dir(destination))
}

func TestFetchDirectRunsSideBySide(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat(request.URL.Path, 10_000))
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	dir := t.TempDir()
	var wait sync.WaitGroup
	for i := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			path := fmt.Sprintf("/set-%d", i)
			destination := filepath.Join(dir, path[1:])
			if _, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL+path, nil, 10_000, 1<<20), destination); err != nil {
				t.Errorf("%s: %v", path, err)
				return
			}
			if written, err := os.ReadFile(destination); err != nil || string(written) != strings.Repeat(path, 10_000) {
				t.Errorf("%s holds %d bytes (%v), not its own body", path, len(written), err)
			}
		}()
	}
	wait.Wait()
}

func TestFetchDirectSaysUnavailableWithoutARunningCoreOrTheRoute(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Error("an unavailable fetch reached the origin")
	}))
	t.Cleanup(origin.Close)

	if currentCoreService() != nil {
		t.Fatal("a core from another test is still published")
	}
	client := directFetchClientOnControlPlane(t)
	_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 5000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchUnavailablePrefix) {
		t.Fatalf("FetchDirect with no core: err = %v, want the unavailable prefix", err)
	}

	oldClient := directFetchClientOn(t, http.NotFoundHandler())
	_, err = oldClient.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 5000, 1024), filepath.Join(t.TempDir(), "b"))
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchUnavailablePrefix) {
		t.Fatalf("FetchDirect against an Extension without the route: err = %v, want the unavailable prefix", err)
	}
}

func TestFetchDirectRefusesAnAnswerThatEndsWithoutTheCoresWord(t *testing.T) {
	client := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(directFetchAnswerHeader, `{"status":200,"headers":{}}`)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("half of it"))
	}))
	destination := filepath.Join(t.TempDir(), "short")
	if _, err := client.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 5000, 1024), destination); err == nil {
		t.Fatal("FetchDirect accepted an answer with no completion word")
	} else if !strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("an answer cut before the core's word: err = %v, want the interrupted prefix", err)
	}
	directoryHolds(t, filepath.Dir(destination))
}

func TestFetchDirectRefusesWhatCannotBeADownload(t *testing.T) {
	var asked atomic.Int32
	client := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		asked.Add(1)
		writer.WriteHeader(http.StatusTeapot)
	}))
	dir := t.TempDir()
	destination := filepath.Join(dir, "x")
	cases := map[string]struct {
		request, destination string
	}{
		"not JSON":          {"{", destination},
		"ftp":               {directFetchRequestJSON(t, "ftp://example.com/a", nil, 5000, 1024), destination},
		"no host":           {directFetchRequestJSON(t, "https:///a", nil, 5000, 1024), destination},
		"no timeout":        {directFetchRequestJSON(t, "https://example.com/a", nil, 0, 1024), destination},
		"timeout too short": {directFetchRequestJSON(t, "https://example.com/a", nil, 999, 1024), destination},
		"timeout too long":  {directFetchRequestJSON(t, "https://example.com/a", nil, 300_001, 1024), destination},
		"no limit":          {directFetchRequestJSON(t, "https://example.com/a", nil, 5000, 0), destination},
		"limit too large":   {directFetchRequestJSON(t, "https://example.com/a", nil, 5000, directFetchMaximumBytes+1), destination},
		"no destination":    {directFetchRequestJSON(t, "https://example.com/a", nil, 5000, 1024), ""},
	}
	for name, c := range cases {
		if _, err := client.FetchDirect(c.request, c.destination); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.HasPrefix(err.Error(), DirectFetchUnavailablePrefix) {
			t.Errorf("%s: refused as unavailable (%v); the request itself is wrong", name, err)
		}
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("%d refused request(s) still reached the Extension", n)
	}
	directoryHolds(t, dir)
}

func TestDirectFetchRouteRefusesWhatCannotBeADownload(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Error("a refused request reached the origin")
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	for name, body := range map[string]string{
		"not JSON":        "{",
		"file":            directFetchRequestJSON(t, "file:///etc/hosts", nil, 5000, 1024),
		"no scheme":       strings.Replace(directFetchRequestJSON(t, origin.URL, nil, 5000, 1024), "http://", "", 1),
		"no limit":        directFetchRequestJSON(t, origin.URL, nil, 5000, 0),
		"forever":         directFetchRequestJSON(t, origin.URL, nil, 1<<40, 1024),
		"limit too large": directFetchRequestJSON(t, origin.URL, nil, 5000, directFetchMaximumBytes+1),
	} {
		response, _, err := postDirectFetchRoute(t, context.Background(), client, body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: the route answered %d, want 400", name, response.StatusCode)
		}
	}
}

func TestDirectFetchRouteAnswersOnlyOnTheAppGroupSocket(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "inside")
	}))
	t.Cleanup(origin.Close)
	startDirectFetchCore(t, rejectEverythingYAML)

	serve := func(network, address string) string {
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		server := &mhttp.Server{Handler: mhttp.HandlerFunc(serveDirectFetch)}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })
		return listener.Addr().String()
	}
	body := directFetchRequestJSON(t, origin.URL, nil, 5000, 1024)

	tcp := serve("tcp", "127.0.0.1:0")
	response, err := http.Post("http://"+tcp+privateAPIPrefix+directFetchRoute, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("over TCP the route answered %d, want 404", response.StatusCode)
	}

	unix := serve("unix", shortClashSocketPath(t))
	client, err := NewAPIClient(unix, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchDirect(body, filepath.Join(t.TempDir(), "a")); err != nil {
		t.Fatalf("control: over the Unix socket the same handler refused: %v", err)
	}
}

type redirectChain struct {
	a, b *httptest.Server
	mu   sync.Mutex
	seen map[string]http.Header
}

func newRedirectChain(t *testing.T) *redirectChain {
	t.Helper()
	chain := &redirectChain{seen: map[string]http.Header{}}
	record := func(request *http.Request) {
		chain.mu.Lock()
		chain.seen[request.Host+request.URL.Path] = request.Header.Clone()
		chain.mu.Unlock()
	}
	chain.b = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		record(request)
		switch request.URL.Path {
		case "/cross":
			http.Redirect(writer, request, chain.a.URL+"/back", http.StatusFound)
		case "/gz":
			if !strings.Contains(request.Header.Get("Accept-Encoding"), "gzip") {
				http.Error(writer, "gzip only", http.StatusNotAcceptable)
				return
			}
			writer.Header().Set("Content-Encoding", "gzip")
			compressor := gzip.NewWriter(writer)
			_, _ = io.WriteString(compressor, "decoded across origins")
			_ = compressor.Close()
		default:
			_, _ = io.WriteString(writer, "b")
		}
	}))
	t.Cleanup(chain.b.Close)
	chain.a = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		record(request)
		switch request.URL.Path {
		case "/start":
			http.Redirect(writer, request, chain.b.URL+"/cross", http.StatusFound)
		case "/start-gz":
			http.Redirect(writer, request, chain.b.URL+"/gz", http.StatusFound)
		case "/same":
			http.Redirect(writer, request, "/same-final", http.StatusFound)
		case "/hop1":
			http.Redirect(writer, request, "/hop2", http.StatusFound)
		case "/hop2":
			http.Redirect(writer, request, "/hop3", http.StatusFound)
		case "/hop3":
			http.Redirect(writer, request, "/done", http.StatusFound)
		case "/loop":
			http.Redirect(writer, request, "/loop", http.StatusFound)
		case "/set-cookie":
			http.SetCookie(writer, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
			http.Redirect(writer, request, "/need-cookie", http.StatusFound)
		default:
			_, _ = io.WriteString(writer, "a")
		}
	}))
	t.Cleanup(chain.a.Close)
	return chain
}

func (c *redirectChain) headersAt(server *httptest.Server, path string) http.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[strings.TrimPrefix(server.URL, "http://")+path]
}

func directFetchRedirectJSON(t *testing.T, url string, headers map[string][]string, policy string, maximumRedirects *int) string {
	t.Helper()
	request := map[string]any{"url": url, "headers": headers, "timeoutMilliseconds": 10_000, "maximumBytes": 1 << 20}
	if policy != "" {
		request["redirectPolicy"] = policy
	}
	if maximumRedirects != nil {
		request["maximumRedirects"] = *maximumRedirects
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func TestFetchDirectRedirectsTheWayTheAppDoes(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)
	headers := map[string][]string{
		"User-Agent": {"clash.meta"}, "Authorization": {"Bearer t0k3n"}, "Cookie": {"c=1"},
		"If-None-Match": {`"v1"`}, "X-Custom": {"x"},
	}

	if _, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/start", headers, "", nil), filepath.Join(t.TempDir(), "a")); err != nil {
		t.Fatalf("FetchDirect across origins: %v", err)
	}
	for _, hop := range []struct {
		server *httptest.Server
		path   string
	}{{chain.b, "/cross"}, {chain.a, "/back"}} {
		seen := chain.headersAt(hop.server, hop.path)
		if seen == nil {
			t.Fatalf("%s was never asked", hop.path)
		}
		if seen.Get("User-Agent") != "clash.meta" {
			t.Errorf("%s: User-Agent %q, want the App's", hop.path, seen.Get("User-Agent"))
		}
		for _, name := range []string{"Authorization", "Cookie", "If-None-Match", "X-Custom", "Referer"} {
			if value := seen.Get(name); value != "" {
				t.Errorf("%s: %s %q crossed an origin", hop.path, name, value)
			}
		}
	}

	if _, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/same", headers, "", nil), filepath.Join(t.TempDir(), "b")); err != nil {
		t.Fatalf("FetchDirect within an origin: %v", err)
	}
	seen := chain.headersAt(chain.a, "/same-final")
	for name, want := range map[string]string{"Authorization": "Bearer t0k3n", "If-None-Match": `"v1"`, "X-Custom": "x", "Referer": ""} {
		if seen.Get(name) != want {
			t.Errorf("within the origin %s = %q, want %q", name, seen.Get(name), want)
		}
	}
}

func TestFetchDirectAnswersTheRedirectPastItsLimit(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	for _, c := range []struct {
		limit      *int
		wantStatus int
	}{{nil, http.StatusOK}, {intPointer(3), http.StatusOK}, {intPointer(2), http.StatusFound}, {intPointer(0), http.StatusFound}} {
		answer, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/hop1", nil, "followAcrossOrigins", c.limit), filepath.Join(t.TempDir(), "a"))
		if err != nil {
			t.Fatalf("limit %s: %v", describeLimit(c.limit), err)
		}
		if got := decodeDirectFetchAnswer(t, answer).Status; got != c.wantStatus {
			t.Errorf("limit %s over three hops: status %d, want %d", describeLimit(c.limit), got, c.wantStatus)
		}
	}
}

func TestFetchDirectSameOriginPolicyAnswersACrossOriginRedirect(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	answer, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/start", nil, "sameOrigin", nil), filepath.Join(t.TempDir(), "a"))
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeDirectFetchAnswer(t, answer).Status; got != http.StatusFound {
		t.Fatalf("sameOrigin across origins: status %d, want the 302 itself", got)
	}
	if chain.headersAt(chain.b, "/cross") != nil {
		t.Fatal("sameOrigin followed a redirect to another origin")
	}
	answer, err = client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/same", nil, "sameOrigin", nil), filepath.Join(t.TempDir(), "b"))
	if err != nil || decodeDirectFetchAnswer(t, answer).Status != http.StatusOK {
		t.Fatalf("sameOrigin within the origin: %s, %v", answer, err)
	}
}

func TestFetchDirectKeepsTheCookiesARedirectSets(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	if _, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/set-cookie", nil, "", nil), filepath.Join(t.TempDir(), "a")); err != nil {
		t.Fatal(err)
	}
	if got := chain.headersAt(chain.a, "/need-cookie").Get("Cookie"); got != "session=s1" {
		t.Fatalf("the request after the redirect carried Cookie %q, want the one the redirect set", got)
	}
}

func TestFetchDirectAcceptsAnyServerCertificateOnlyWhenAsked(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "self-signed")
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	request := func(accept bool) string {
		payload, err := json.Marshal(map[string]any{"url": origin.URL, "timeoutMilliseconds": 10_000, "maximumBytes": 1024, "acceptAnyServerCertificate": accept})
		if err != nil {
			t.Fatal(err)
		}
		return string(payload)
	}
	destination := filepath.Join(t.TempDir(), "a")
	if _, err := client.FetchDirect(request(false), destination); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a self-signed origin without acceptAnyServerCertificate: err = %v, want a certificate failure", err)
	} else if strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) || strings.HasPrefix(err.Error(), DirectFetchUnavailablePrefix) {
		t.Fatalf("a refused certificate reads as interrupted or unavailable: %v", err)
	}
	if _, err := client.FetchDirect(request(true), destination); err != nil {
		t.Fatalf("a self-signed origin with acceptAnyServerCertificate: %v", err)
	}
	if written, _ := os.ReadFile(destination); string(written) != "self-signed" {
		t.Fatalf("destination holds %q", written)
	}
}

func TestFetchDirectTellsAnAbsentExtensionFromOneThatHungUp(t *testing.T) {
	missing, err := NewAPIClient(shortClashSocketPath(t), newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	_, err = missing.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 5000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchUnavailablePrefix) {
		t.Fatalf("no socket at all: err = %v, want the unavailable prefix", err)
	}

	hungUp := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, _, _ := writer.(http.Hijacker).Hijack()
		_ = connection.Close()
	}))
	_, err = hungUp.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 5000, 1024), filepath.Join(t.TempDir(), "b"))
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("an Extension that hung up: err = %v, want the interrupted prefix", err)
	}
}

func TestFetchDirectRefusesAnUnknownRedirectPolicy(t *testing.T) {
	for name, request := range map[string]directFetchRequest{
		"unknown policy":  {URL: "https://example.com/", TimeoutMilliseconds: 5000, MaximumBytes: 1024, RedirectPolicy: "anywhere"},
		"negative limit":  {URL: "https://example.com/", TimeoutMilliseconds: 5000, MaximumBytes: 1024, MaximumRedirects: intPointer(-1)},
		"limit too large": {URL: "https://example.com/", TimeoutMilliseconds: 5000, MaximumBytes: 1024, MaximumRedirects: intPointer(21)},
	} {
		if err := request.validate(); err == nil {
			t.Errorf("%s validated", name)
		}
	}
	for _, policy := range []string{"", "followAcrossOrigins", "sameOrigin"} {
		request := directFetchRequest{URL: "https://example.com/", TimeoutMilliseconds: 5000, MaximumBytes: 1024, RedirectPolicy: policy, MaximumRedirects: intPointer(20)}
		if err := request.validate(); err != nil {
			t.Errorf("policy %q refused: %v", policy, err)
		}
	}
}

func intPointer(value int) *int { return &value }

func describeLimit(limit *int) string {
	if limit == nil {
		return "unset"
	}
	return fmt.Sprint(*limit)
}

func TestFetchDirectCallsAnAnswerCutMidBodyInterrupted(t *testing.T) {
	client := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(directFetchAnswerHeader, `{"status":200,"headers":{}}`)
		writer.Header().Set("Trailer", directFetchResultTrailer)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(strings.Repeat("x", 512)))
		writer.(http.Flusher).Flush()
		connection, _, _ := writer.(http.Hijacker).Hijack()
		_ = connection.Close()
	}))
	destination := filepath.Join(t.TempDir(), "cut")
	_, err := client.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 5000, 1024), destination)
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("an answer cut mid-body: err = %v, want the interrupted prefix", err)
	}
	directoryHolds(t, filepath.Dir(destination))
}

func TestDirectFetchJarRefusesACookieForAPublicSuffix(t *testing.T) {
	jar, err := newDirectFetchJar()
	if err != nil {
		t.Fatal(err)
	}
	from, _ := url.Parse("https://foo.co.uk/start")
	jar.SetCookies(from, []*mhttp.Cookie{
		{Name: "planted", Value: "x", Domain: "co.uk", Path: "/"},
		{Name: "own", Value: "y", Domain: "foo.co.uk", Path: "/"},
	})
	other, _ := url.Parse("https://bar.co.uk/end")
	if cookies := jar.Cookies(other); len(cookies) != 0 {
		t.Fatalf("bar.co.uk is sent %v, set by foo.co.uk for the public suffix", cookies)
	}
	sub, _ := url.Parse("https://www.foo.co.uk/end")
	if cookies := jar.Cookies(sub); len(cookies) != 1 || cookies[0].Name != "own" {
		t.Fatalf("control: www.foo.co.uk is sent %v, want foo.co.uk's own cookie", cookies)
	}
}

func TestDirectFetchOriginIsTheOneTheAppReads(t *testing.T) {
	origin := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return directFetchOrigin(u)
	}
	for _, same := range [][2]string{
		{"https://EXAMPLE.com/a", "https://example.com/b"},
		{"http://example.com:080/a", "http://example.com:80/b"},
		{"HTTP://[::1]:8080/a", "http://[::1]:8080/b"},
	} {
		if origin(same[0]) != origin(same[1]) {
			t.Errorf("%s and %s are one origin to the App", same[0], same[1])
		}
	}
	for _, apart := range [][2]string{
		{"https://example.com/a", "http://example.com/b"},
		{"https://example.com/a", "https://example.com:443/b"},
		{"https://example.com/a", "https://www.example.com/b"},
	} {
		if origin(apart[0]) == origin(apart[1]) {
			t.Errorf("%s and %s are two origins to the App", apart[0], apart[1])
		}
	}

	for _, policy := range []string{"", directFetchSameOrigin} {
		first, _ := mhttp.NewRequest(mhttp.MethodGet, "https://EXAMPLE.com/start", nil)
		first.Header.Set("Authorization", "Bearer t0k3n")
		first.Header.Set("Cookie", "c=1")
		next, _ := mhttp.NewRequest(mhttp.MethodGet, "https://example.com/end", nil)
		next.Header.Set("Referer", "https://EXAMPLE.com/start")
		if err := directFetchRedirect(directFetchRequest{RedirectPolicy: policy})(next, []*mhttp.Request{first}); err != nil {
			t.Fatalf("policy %q: %v", policy, err)
		}
		if next.Header.Get("Authorization") != "Bearer t0k3n" || next.Header.Get("Cookie") != "c=1" || next.Header.Get("Referer") != "" {
			t.Errorf("policy %q: a hop within the origin carries %v, want the request as it was", policy, next.Header)
		}
	}
}

func TestDirectFetchTellsAFailedWriteFromACutAnswer(t *testing.T) {
	answer := func(body io.Reader) *http.Response {
		return &http.Response{Body: io.NopCloser(body), Trailer: http.Header{}}
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writeDirectFetchBody(context.Background(), answer(strings.NewReader("body")), readOnly, 1024, http.StatusOK)
	if err == nil || errors.As(err, new(directFetchInterruption)) {
		t.Fatalf("a failed write: err = %v, want a failure that is not an interruption", err)
	}

	writable, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = writeDirectFetchBody(context.Background(), answer(io.MultiReader(strings.NewReader("part"), iotestErrReader{io.ErrUnexpectedEOF})), writable, 1024, http.StatusOK)
	if !errors.As(err, new(directFetchInterruption)) {
		t.Fatalf("a failed read: err = %v, want an interruption", err)
	}
}

type iotestErrReader struct{ err error }

func (r iotestErrReader) Read([]byte) (int, error) { return 0, r.err }

func TestFetchDirectSameOriginStopsALoop(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	started := time.Now()
	_, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/loop", nil, "sameOrigin", nil), filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.Contains(err.Error(), "stopped after 20 redirects") {
		t.Fatalf("sameOrigin around a loop: err = %v, want it stopped after 20", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the loop ran %s; it should stop by count, not by the 10 s deadline", elapsed)
	}
}

func TestFetchDirectAppDeadlineMidBodyIsNotInterrupted(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	client := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(directFetchAnswerHeader, `{"status":200,"headers":{}}`)
		writer.Header().Set("Trailer", directFetchResultTrailer)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("half"))
		writer.(http.Flusher).Flush()
		select {
		case <-release:
		case <-request.Context().Done():
		}
	}))
	_, err := client.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 1000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("the App's deadline mid-body: err = %v, want a failure that is not an interruption", err)
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("the App's deadline mid-body: err = %v, want the deadline named", err)
	}
}

func TestDirectFetchCallsOnlyACutConnectionInterrupted(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(writer, "this is not gzip")
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("a body that is not the gzip it says: err = %v, want gzip's failure, not an interruption", err)
	}
	for _, cut := range []error{io.ErrUnexpectedEOF, net.ErrClosed, io.ErrClosedPipe, syscall.ECONNRESET,
		&net.OpError{Op: "read", Err: syscall.ECONNRESET}} {
		if !directFetchConnectionCut(fmt.Errorf("read body: %w", cut)) {
			t.Errorf("%v is a cut connection", cut)
		}
	}
	if directFetchConnectionCut(errors.New("gzip: invalid header")) {
		t.Error("a decoding failure is not a cut connection")
	}
}

func TestDirectFetchSameOriginHopDropsACookieARedirectSetAnew(t *testing.T) {
	for _, hosts := range [][2]string{{"example.com", "example.com"}, {"EXAMPLE.com", "example.com"}} {
		first, _ := mhttp.NewRequest(mhttp.MethodGet, "https://"+hosts[0]+"/start", nil)
		first.Header.Set("Cookie", "session=old; theme=dark")
		first.Header.Set("Authorization", "Bearer t0k3n")
		redirect := &mhttp.Response{Header: mhttp.Header{"Set-Cookie": {"session=new; Path=/"}}}
		next, _ := mhttp.NewRequest(mhttp.MethodGet, "https://"+hosts[1]+"/end", nil)
		next.Response = redirect
		if hosts[0] == hosts[1] {
			next.Header.Set("Cookie", "theme=dark")
			next.Header.Set("Authorization", "Bearer t0k3n")
		}
		if err := directFetchRedirect(directFetchRequest{})(next, []*mhttp.Request{first}); err != nil {
			t.Fatal(err)
		}
		if got := next.Header.Get("Cookie"); got != "theme=dark" {
			t.Errorf("%s -> %s: Cookie %q, want the old session dropped and the rest kept", hosts[0], hosts[1], got)
		}
		if got := next.Header.Get("Authorization"); got != "Bearer t0k3n" {
			t.Errorf("%s -> %s: Authorization %q", hosts[0], hosts[1], got)
		}
	}
}

func TestDirectFetchTruncatedGzipContentIsNotInterrupted(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Set("Content-Length", "2")
		_, _ = writer.Write([]byte{0x1f, 0x8b})
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("a whole transfer of a cut gzip stream: err = %v, want a failure that is not an interruption", err)
	}
}

func TestDirectFetchWriteFailureAfterAFailedReadIsTheWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{Body: io.NopCloser(oneByteThenError{err: io.ErrUnexpectedEOF}), Trailer: http.Header{}}
	_, err = writeDirectFetchBody(context.Background(), response, readOnly, 1024, http.StatusOK)
	if err == nil || errors.As(err, new(directFetchInterruption)) {
		t.Fatalf("a write that failed on the last bytes of a failed read: err = %v, want the write's failure", err)
	}
}

type oneByteThenError struct{ err error }

func (r oneByteThenError) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, r.err
}

func TestFetchDirectAsksForGzipAcrossOrigins(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "a")
	answer, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/start-gz", nil, "", nil), destination)
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeDirectFetchAnswer(t, answer).Status; status != http.StatusOK {
		t.Fatalf("the hop across origins answered %d; it did not ask for gzip", status)
	}
	if written, _ := os.ReadFile(destination); string(written) != "decoded across origins" {
		t.Fatalf("destination holds %q, want the decoded body", written)
	}
}

func TestDirectFetchRestoresWithheldCredentialsBackAtTheFirstSpelling(t *testing.T) {
	first, _ := mhttp.NewRequest(mhttp.MethodGet, "https://example.com/start", nil)
	first.Header.Set("Authorization", "Bearer t0k3n")
	first.Header.Set("Cookie", "theme=dark")
	middle, _ := mhttp.NewRequest(mhttp.MethodGet, "https://EXAMPLE.com/middle", nil)
	final, _ := mhttp.NewRequest(mhttp.MethodGet, "https://example.com/final", nil)
	if err := directFetchRedirect(directFetchRequest{})(final, []*mhttp.Request{first, middle}); err != nil {
		t.Fatal(err)
	}
	if final.Header.Get("Authorization") != "Bearer t0k3n" || final.Header.Get("Cookie") != "theme=dark" {
		t.Fatalf("back at the first spelling the hop carries %v, want the credentials the copier withheld", final.Header)
	}
}

func TestFetchDirectAsksForGzipAcrossOriginsAfterARange(t *testing.T) {
	chain := newRedirectChain(t)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	destination := filepath.Join(t.TempDir(), "a")
	answer, err := client.FetchDirect(directFetchRedirectJSON(t, chain.a.URL+"/start-gz", map[string][]string{"Range": {"bytes=0-"}}, "", nil), destination)
	if err != nil {
		t.Fatal(err)
	}
	if status := decodeDirectFetchAnswer(t, answer).Status; status != http.StatusOK {
		t.Fatalf("the hop across origins answered %d; it did not ask for gzip", status)
	}
	if written, _ := os.ReadFile(destination); string(written) != "decoded across origins" {
		t.Fatalf("destination holds %q, want the decoded body", written)
	}
}

func TestFetchDirectPassesABodylessGzipAnswerAsItCame(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Set("ETag", `"v1"`)
		writer.WriteHeader(http.StatusNotModified)
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)

	answer, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), filepath.Join(t.TempDir(), "a"))
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeDirectFetchAnswer(t, answer)
	if decoded.Status != http.StatusNotModified || http.Header(decoded.Headers).Get("Content-Encoding") != "gzip" || decoded.Bytes != 0 {
		t.Fatalf("a bodyless 304 marked gzip: answer %s, want it as it came", answer)
	}
}

func TestDirectFetchKeepsTheAppsRefererOnlyWithinTheOrigin(t *testing.T) {
	first, _ := mhttp.NewRequest(mhttp.MethodGet, "https://example.com/start", nil)
	first.Header.Set("Referer", "https://app.example/")
	within, _ := mhttp.NewRequest(mhttp.MethodGet, "https://example.com/end", nil)
	within.Header.Set("Referer", "https://example.com/start")
	if err := directFetchRedirect(directFetchRequest{})(within, []*mhttp.Request{first}); err != nil {
		t.Fatal(err)
	}
	if got := within.Header.Get("Referer"); got != "https://app.example/" {
		t.Fatalf("within the origin Referer %q, want the App's", got)
	}
	across, _ := mhttp.NewRequest(mhttp.MethodGet, "https://other.example/end", nil)
	across.Header.Set("Referer", "https://example.com/start")
	if err := directFetchRedirect(directFetchRequest{})(across, []*mhttp.Request{first}); err != nil {
		t.Fatal(err)
	}
	if got := across.Header.Get("Referer"); got != "" {
		t.Fatalf("out of the origin Referer %q, want none", got)
	}
}

func TestDirectFetchPassesGzipItDidNotAskFor(t *testing.T) {
	request, _ := mhttp.NewRequest(mhttp.MethodGet, "https://example.com/", nil)
	request.Header.Set("Range", "bytes=0-")
	response := &mhttp.Response{
		Request:       request,
		Header:        mhttp.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"10"}},
		ContentLength: 10,
		Body:          io.NopCloser(strings.NewReader("0123456789")),
	}
	raw, body := directFetchDecoded(response)
	if body != io.Reader(raw) || response.Header.Get("Content-Encoding") != "gzip" || response.ContentLength != 10 {
		t.Fatalf("gzip not asked for was decoded: headers %v, length %d", response.Header, response.ContentLength)
	}
}

func TestDirectFetchCutBodyOfAFailureStatusIsThatStatus(t *testing.T) {
	_, client := startDirectFetchCore(t, rejectEverythingYAML)
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusNotFound, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Length", "1000")
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(strings.Repeat("e", 100)))
			writer.(http.Flusher).Flush()
			connection, _, _ := writer.(http.Hijacker).Hijack()
			_ = connection.Close()
		}))
		_, err := client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1<<20), filepath.Join(t.TempDir(), "a"))
		response, _, routeErr := postDirectFetchRoute(t, context.Background(), client, directFetchRequestJSON(t, origin.URL, nil, 10_000, 1<<20))
		origin.Close()
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		word := response.Trailer.Get(directFetchResultTrailer)
		if markedInterrupted := strings.HasPrefix(word, DirectFetchInterruptedPrefix); markedInterrupted != (status == http.StatusOK) {
			t.Errorf("HTTP %d cut mid-body: the core's last word %q", status, word)
		}
		if err == nil {
			t.Fatalf("HTTP %d cut mid-body: succeeded", status)
		}
		interrupted := strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix)
		if status == http.StatusOK && !interrupted {
			t.Errorf("HTTP 200 cut mid-body: err = %v, want the interrupted prefix", err)
		}
		if status != http.StatusOK && (interrupted || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", status))) {
			t.Errorf("HTTP %d cut mid-body: err = %v, want an ordinary failure naming the status", status, err)
		}
	}
}

func TestFetchDirectAnswerOfAFailureStatusCutOnTheWayIsThatStatus(t *testing.T) {
	cutAnswer := func(status int, trailer string) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set(directFetchAnswerHeader, fmt.Sprintf(`{"status":%d,"headers":{}}`, status))
			writer.Header().Set("Trailer", directFetchResultTrailer)
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte("part"))
			if trailer == "end without a word" {
				return
			}
			if trailer != "" {
				writer.Header().Set(directFetchResultTrailer, trailer)
				return
			}
			writer.(http.Flusher).Flush()
			connection, _, _ := writer.(http.Hijacker).Hijack()
			_ = connection.Close()
		})
	}
	for _, c := range []struct {
		name            string
		status          int
		trailer         string
		wantInterrupted bool
	}{
		{"200 cut on the way", http.StatusOK, "", true},
		{"429 cut on the way", http.StatusTooManyRequests, "", false},
		{"404 cut before the core's word", http.StatusNotFound, "", false},
		{"404 ended without the core's word", http.StatusNotFound, "end without a word", false},
		{"200 ended without the core's word", http.StatusOK, "end without a word", true},
		{"401 marked interrupted by an older core", http.StatusUnauthorized, DirectFetchInterruptedPrefix + "unexpected EOF", false},
		{"200 marked interrupted", http.StatusOK, DirectFetchInterruptedPrefix + "unexpected EOF", true},
	} {
		client := directFetchClientOn(t, cutAnswer(c.status, c.trailer))
		destination := filepath.Join(t.TempDir(), "a")
		_, err := client.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 5000, 1024), destination)
		if err == nil {
			t.Fatalf("%s: succeeded", c.name)
		}
		if got := strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix); got != c.wantInterrupted {
			t.Errorf("%s: err = %v, interrupted %v, want %v", c.name, err, got, c.wantInterrupted)
		}
		if !c.wantInterrupted && !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", c.status)) {
			t.Errorf("%s: err = %v, want the status named", c.name, err)
		}
		directoryHolds(t, filepath.Dir(destination))
	}
}

func TestFetchDirectNamesAKnownFailureStatusInEveryFailure(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	held := directFetchClientOn(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(directFetchAnswerHeader, `{"status":429,"headers":{}}`)
		writer.Header().Set("Trailer", directFetchResultTrailer)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("slow"))
		writer.(http.Flusher).Flush()
		select {
		case <-release:
		case <-request.Context().Done():
		}
	}))
	_, err := held.FetchDirect(directFetchRequestJSON(t, "https://example.com/sub", nil, 1000, 1024), filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "deadline exceeded") ||
		strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("a 429 past the App's deadline: err = %v, want the deadline and the status, not interrupted", err)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "4096")
		writer.WriteHeader(http.StatusTooManyRequests)
		_, _ = writer.Write([]byte(strings.Repeat("x", 4096)))
	}))
	t.Cleanup(origin.Close)
	_, client := startDirectFetchCore(t, rejectEverythingYAML)
	_, err = client.FetchDirect(directFetchRequestJSON(t, origin.URL, nil, 10_000, 1024), filepath.Join(t.TempDir(), "b"))
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "1024") ||
		strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("a 429 over the limit: err = %v, want the limit and the status, not interrupted", err)
	}
}

func TestDirectFetchSuccessIsTwoHundredsOnly(t *testing.T) {
	_, client := startDirectFetchCore(t, rejectEverythingYAML)
	cutWith := func(status int, headers map[string]string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			for name, value := range headers {
				writer.Header().Set(name, value)
			}
			writer.Header().Set("Content-Length", "1000")
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(strings.Repeat("p", 100)))
			writer.(http.Flusher).Flush()
			connection, _, _ := writer.(http.Hijacker).Hijack()
			_ = connection.Close()
		}))
	}
	partial := cutWith(http.StatusPartialContent, map[string]string{"Content-Range": "bytes 0-999/5000"})
	t.Cleanup(partial.Close)
	_, err := client.FetchDirect(directFetchRequestJSON(t, partial.URL, nil, 10_000, 1<<20), filepath.Join(t.TempDir(), "a"))
	if err == nil || !strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) {
		t.Fatalf("HTTP 206 cut mid-body: err = %v, want interrupted", err)
	}
	redirect := cutWith(http.StatusFound, map[string]string{"Location": "http://127.0.0.1:1/elsewhere"})
	t.Cleanup(redirect.Close)
	_, err = client.FetchDirect(directFetchRedirectJSON(t, redirect.URL, nil, "", intPointer(0)), filepath.Join(t.TempDir(), "b"))
	if err == nil || strings.HasPrefix(err.Error(), DirectFetchInterruptedPrefix) || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("a 302 answered as it stands, cut mid-body: err = %v, want an ordinary failure naming HTTP 302", err)
	}
}
