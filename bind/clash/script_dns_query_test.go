package clash

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/tunnel"
	mhttp "github.com/metacubex/http"
	mhttptest "github.com/metacubex/http/httptest"

	D "github.com/miekg/dns"
)

type scriptDNSStub struct {
	addr        string
	hits        atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	hold        time.Duration
	silent      bool
}

func (s *scriptDNSStub) answer(request *D.Msg) *D.Msg {
	s.hits.Add(1)
	now := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for {
		seen := s.maxInFlight.Load()
		if now <= seen || s.maxInFlight.CompareAndSwap(seen, now) {
			break
		}
	}
	if s.hold > 0 {
		time.Sleep(s.hold)
	}
	reply := new(D.Msg)
	reply.SetReply(request)
	question := request.Question[0]
	switch question.Name {
	case "example.com.":
		switch question.Qtype {
		case D.TypeA:
			reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")})
		case D.TypeAAAA:
			reply.Answer = append(reply.Answer, &D.AAAA{Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")})
		}
	default:
		reply.Rcode = D.RcodeNameError
	}
	return reply
}

func startScriptDNSUDP(t *testing.T, hold time.Duration, silent bool) *scriptDNSStub {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stub := &scriptDNSStub{addr: conn.LocalAddr().String(), hold: hold, silent: silent}
	server := &D.Server{PacketConn: conn, Handler: D.HandlerFunc(func(writer D.ResponseWriter, request *D.Msg) {
		if stub.silent {
			stub.hits.Add(1)
			return
		}
		_ = writer.WriteMsg(stub.answer(request))
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return stub
}

func startScriptDNSDoH(t *testing.T) (*scriptDNSStub, string) {
	t.Helper()
	stub := &scriptDNSStub{}
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		var wire []byte
		var err error
		if request.Method == stdhttp.MethodGet {
			wire, err = base64.RawURLEncoding.DecodeString(request.URL.Query().Get("dns"))
		} else {
			wire, err = io.ReadAll(request.Body)
		}
		query := new(D.Msg)
		if err != nil || query.Unpack(wire) != nil || len(query.Question) == 0 {
			stdhttp.Error(writer, "bad query", stdhttp.StatusBadRequest)
			return
		}
		packed, _ := stub.answer(query).Pack()
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(packed)
	}))
	t.Cleanup(server.Close)
	stub.addr = server.Listener.Addr().String()
	return stub, "https://" + stub.addr + "/dns-query#skip-cert-verify=true"
}

func withScriptDNSCore(t *testing.T, rule string) {
	t.Helper()
	cfg, err := config.Parse([]byte("mode: rule\nrules:\n  - " + rule + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	previousProxies, previousProviders, previousStatus := tunnel.Proxies(), tunnel.Providers(), tunnel.Status()
	previousRules, previousRuleProviders := tunnel.Rules(), tunnel.RuleProviders()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.UpdateProxies(previousProxies, previousProviders)
		tunnel.UpdateRules(previousRules, nil, previousRuleProviders)
		switch previousStatus {
		case tunnel.Suspend:
			tunnel.OnSuspend()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		}
	})
}

type scriptDNSTestAnswer struct {
	Domain    string `json:"domain"`
	Protocol  string `json:"protocol"`
	Server    string `json:"server"`
	FromCache bool   `json:"fromCache"`
	Answers   []struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
		TTL   uint32 `json:"ttl"`
	} `json:"answers"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func scriptDNSTestScene(stub *scriptDNSStub) string {
	return fmt.Sprintf("server asked %d times, default interface %q index %d, tunnel %s",
		stub.hits.Load(), dialer.DefaultInterface.Load(), publishedInterfaceIndex.Load(), tunnel.Status())
}

func askScriptDNS(t *testing.T, request any) scriptDNSTestAnswer {
	t.Helper()
	text, ok := request.(string)
	if !ok {
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		text = string(encoded)
	}
	payload := ScriptDNSQueryJSON(text)
	var answer scriptDNSTestAnswer
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil {
		t.Fatalf("the export must return the documented JSON, got %q: %v", payload, err)
	}
	return answer
}

func (a scriptDNSTestAnswer) values() []string {
	var values []string
	for _, answer := range a.Answers {
		values = append(values, answer.Type+" "+answer.Value)
	}
	return values
}

func TestScriptDNSQueryAsksTheNamedUDPServerByTheRules(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub := startScriptDNSUDP(t, 0, false)
	logs := captureWarnings(t)

	answer := askScriptDNS(t, map[string]any{"domain": "example.com", "protocol": "udp", "server": stub.addr, "timeoutMilliseconds": 3000})
	if answer.Error != nil {
		t.Fatalf("%s: %s", answer.Error.Code, answer.Error.Message)
	}
	if answer.Domain != "example.com" || answer.Protocol != "udp" || answer.Server != stub.addr || answer.FromCache {
		t.Fatalf("the answer's head: %+v", answer)
	}
	if got := strings.Join(answer.values(), ", "); got != "A 192.0.2.1, AAAA 2001:db8::1" {
		t.Fatalf("A and AAAA by default, in that order: %s", got)
	}
	if answer.Answers[0].Name != "example.com." || answer.Answers[0].TTL != 300 {
		t.Fatalf("the record's own name and TTL: %+v", answer.Answers[0])
	}
	if lines := logs.matching("[script-dns] udp " + stub.addr + " example.com A,AAAA → 2 answers in "); len(lines) != 1 {
		t.Fatalf("one log line per query, got %q", logs.matching("[script-dns]"))
	}
	if lines := logs.matching("--> " + stub.addr + " match Match using DIRECT"); len(lines) == 0 {
		t.Fatal("the query to the named server did not go through the rules")
	}
}

func TestScriptDNSQueryIsRefusedWhereTheRulesRefuse(t *testing.T) {
	withScriptDNSCore(t, "MATCH,REJECT")
	stub := startScriptDNSUDP(t, 0, false)

	answer := askScriptDNS(t, map[string]any{"domain": "example.com", "protocol": "udp", "server": stub.addr, "timeoutMilliseconds": 300})
	if answer.Error == nil {
		t.Fatalf("the rules refuse the server, and the query was answered: %v", answer.values())
	}
	if stub.hits.Load() != 0 {
		t.Fatalf("the server was asked %d times past a REJECT", stub.hits.Load())
	}
}

func TestScriptDNSQueryAsksTheNamedDoHServer(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub, server := startScriptDNSDoH(t)

	answer := askScriptDNS(t, map[string]any{"domain": "example.com", "protocol": "doh", "server": server, "types": []string{"A"}})
	if answer.Error != nil {
		t.Fatalf("%s: %s", answer.Error.Code, answer.Error.Message)
	}
	if got := strings.Join(answer.values(), ", "); got != "A 192.0.2.1" {
		t.Fatalf("only the type asked: %s", got)
	}
	if answer.Protocol != "doh" || answer.Server != "https://"+stub.addr+"/dns-query" {
		t.Fatalf("protocol %q server %q", answer.Protocol, answer.Server)
	}
	if stub.hits.Load() != 1 {
		t.Fatalf("one type, one query; the server was asked %d times", stub.hits.Load())
	}
}

func TestScriptDNSQueryToANamedServerIsNotCached(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub := startScriptDNSUDP(t, 0, false)

	for i := 0; i < 2; i++ {
		answer := askScriptDNS(t, map[string]any{"domain": "example.com", "server": stub.addr, "types": []string{"A"}})
		if answer.Error != nil {
			t.Fatalf("call %d: %+v (%s)", i, *answer.Error, scriptDNSTestScene(stub))
		}
		if answer.FromCache {
			t.Fatalf("call %d said fromCache: %+v", i, answer)
		}
	}
	if stub.hits.Load() != 2 {
		t.Fatalf("two calls asked the server %d times", stub.hits.Load())
	}
}

func TestScriptDNSQueryReadsTheProtocolOffTheServer(t *testing.T) {
	for _, c := range []struct {
		protocol, server string
		wantProtocol     string
		wantNet          string
		wantAddr         string
		wantH3           bool
		wantProxy        string
		wantShown        string
	}{
		{"", "1.1.1.1", "udp", "", "1.1.1.1:53", false, dns.RespectRules, "1.1.1.1:53"},
		{"", "udp://1.1.1.1:5353", "udp", "", "1.1.1.1:5353", false, dns.RespectRules, "1.1.1.1:5353"},
		{"udp", "2606:4700:4700::1111", "udp", "", "[2606:4700:4700::1111]:53", false, dns.RespectRules, "[2606:4700:4700::1111]:53"},
		{"", "https://dns.example/dns-query", "doh", "https", "https://dns.example:443/dns-query", false, dns.RespectRules, "https://dns.example:443/dns-query"},
		{"", "h3://dns.example/dns-query", "doh3", "https", "https://dns.example:443/dns-query", true, dns.RespectRules, "https://dns.example:443/dns-query"},
		{"doh3", "https://dns.example/dns-query", "doh3", "https", "https://dns.example:443/dns-query", true, dns.RespectRules, "https://dns.example:443/dns-query"},
		{"", "quic://dns.example", "quic", "quic", "dns.example:853", false, dns.RespectRules, "quic://dns.example:853"},
		{"quic", "dns.example:8853", "quic", "quic", "dns.example:8853", false, dns.RespectRules, "quic://dns.example:8853"},
		{"DoH", "https://dns.example/dns-query#节点 A", "doh", "https", "https://dns.example:443/dns-query", false, "节点 A", "https://dns.example:443/dns-query"},
	} {
		server, protocol, refusal := scriptDNSServer(c.protocol, c.server)
		if refusal != nil {
			t.Fatalf("%q %q: %s %s", c.protocol, c.server, refusal.Code, refusal.Message)
		}
		if protocol != c.wantProtocol || server.Net != c.wantNet || server.Addr != c.wantAddr || (server.Params["h3"] == "true") != c.wantH3 || server.ProxyName != c.wantProxy {
			t.Fatalf("%q %q: protocol %q net %q addr %q params %v proxy %q", c.protocol, c.server, protocol, server.Net, server.Addr, server.Params, server.ProxyName)
		}
		if shown := scriptDNSServerShown(protocol, server); shown != c.wantShown {
			t.Fatalf("%q %q is shown as %q, want %q", c.protocol, c.server, shown, c.wantShown)
		}
	}
	for _, c := range [][2]string{{"", ""}, {"", "system"}, {"", "SYSTEM"}, {"auto", "1.1.1.1"}} {
		if _, protocol, refusal := scriptDNSServer(c[0], c[1]); refusal != nil || protocol != "auto" {
			t.Fatalf("%q %q is auto, got %q %+v", c[0], c[1], protocol, refusal)
		}
	}
}

func TestScriptDNSQueryRefusesWhatItCannotAsk(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	for _, c := range []struct {
		request any
		code    string
	}{
		{"not json", "INVALID_ARGUMENT"},
		{map[string]any{}, "INVALID_ARGUMENT"},
		{map[string]any{"domain": "  "}, "INVALID_ARGUMENT"},
		{map[string]any{"domain": "example.com", "server": "1.1.1.1", "timeoutMilliseconds": 0}, "INVALID_ARGUMENT"},
		{map[string]any{"domain": "example.com", "server": "1.1.1.1", "timeoutMilliseconds": -5}, "INVALID_ARGUMENT"},
		{map[string]any{"domain": "example.com", "server": "1.1.1.1", "types": []string{"NOPE"}}, "INVALID_ARGUMENT"},
		{map[string]any{"domain": "example.com", "protocol": "tls", "server": "1.1.1.1"}, "UNSUPPORTED_PROTOCOL"},
		{map[string]any{"domain": "example.com", "server": "tls://1.1.1.1"}, "UNSUPPORTED_PROTOCOL"},
		{map[string]any{"domain": "example.com", "protocol": "udp"}, "INVALID_SERVER"},
		{map[string]any{"domain": "example.com", "protocol": "udp", "server": "https://dns.example/dns-query"}, "INVALID_SERVER"},
		{map[string]any{"domain": "example.com", "protocol": "doh", "server": "1.1.1.1"}, "INVALID_SERVER"},
		{map[string]any{"domain": "example.com", "protocol": "quic", "server": "https://dns.example"}, "INVALID_SERVER"},
		{map[string]any{"domain": "example.com", "protocol": "udp", "server": "1.1.1.1:notaport"}, "INVALID_SERVER"},
	} {
		answer := askScriptDNS(t, c.request)
		if answer.Error == nil || answer.Error.Code != c.code || answer.Error.Message == "" {
			t.Fatalf("%v: want %s, got %+v", c.request, c.code, answer.Error)
		}
	}
}

func TestScriptDNSQueryReportsAMissingNameAsNoAnswer(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub := startScriptDNSUDP(t, 0, false)

	answer := askScriptDNS(t, map[string]any{"domain": "missing.example", "server": stub.addr})
	if answer.Error == nil || answer.Error.Code != "NO_ANSWER" || !strings.Contains(answer.Error.Message, "NXDOMAIN") {
		t.Fatalf("an NXDOMAIN: %+v", answer.Error)
	}
}

func TestScriptDNSQueryTimesOutOnASilentServer(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub := startScriptDNSUDP(t, 0, true)

	started := time.Now()
	answer := askScriptDNS(t, map[string]any{"domain": "example.com", "server": stub.addr, "types": []string{"A"}, "timeoutMilliseconds": 200})
	if answer.Error == nil || answer.Error.Code != "TIMEOUT" {
		t.Fatalf("a server that never answers: %+v", answer.Error)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a 200 ms timeout took %v", elapsed)
	}
}

func TestScriptDNSQueryAsksAtMostEightAtATime(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub := startScriptDNSUDP(t, 150*time.Millisecond, false)

	var wait sync.WaitGroup
	failures := make(chan string, 24)
	for i := 0; i < 24; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			payload := ScriptDNSQueryJSON(fmt.Sprintf(`{"domain":"example.com","server":%q,"types":["A"],"timeoutMilliseconds":10000}`, stub.addr))
			if strings.Contains(payload, `"error"`) {
				failures <- payload
			}
		}()
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("a queued query failed: %s (%s)", failure, scriptDNSTestScene(stub))
	}
	if most := stub.maxInFlight.Load(); most > 8 || most < 2 {
		t.Fatalf("at most eight at a time and more than one: the server saw %d at once", most)
	}
}

func TestScriptDNSQueryTimeoutIsBoundedAndDefaulted(t *testing.T) {
	for _, c := range []struct {
		text string
		want time.Duration
	}{
		{`{"domain":"example.com"}`, 3 * time.Second},
		{`{"domain":"example.com","timeoutMilliseconds":1500}`, 1500 * time.Millisecond},
		{`{"domain":"example.com","timeoutMilliseconds":600000}`, 30 * time.Second},
	} {
		request, refusal := parseScriptDNSRequest([]byte(c.text))
		if refusal != nil {
			t.Fatalf("%s: %+v", c.text, refusal)
		}
		if request.timeout != c.want {
			t.Fatalf("%s: timeout %v, want %v", c.text, request.timeout, c.want)
		}
	}
}

func TestScriptDNSQueryNeedsTheRunningCore(t *testing.T) {
	previousStatus := tunnel.Status()
	tunnel.OnSuspend()
	t.Cleanup(func() {
		switch previousStatus {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		}
	})
	answer := askScriptDNS(t, map[string]any{"domain": "example.com", "server": "127.0.0.1:53"})
	if answer.Error == nil || answer.Error.Code != "UNAVAILABLE" {
		t.Fatalf("a named server with the tunnel suspended: %+v", answer.Error)
	}

	previousResolver := resolver.DefaultResolver
	resolver.DefaultResolver = nil
	t.Cleanup(func() { resolver.DefaultResolver = previousResolver })
	answer = askScriptDNS(t, map[string]any{"domain": "example.com", "protocol": "auto"})
	if answer.Error == nil || answer.Error.Code != "UNAVAILABLE" || !strings.Contains(answer.Error.Message, "DNS section is disabled") {
		t.Fatalf("auto without a resolver: %+v", answer.Error)
	}
}

type fakeIPMapper struct{ resolver.Enhancer }

func (fakeIPMapper) FakeIPEnabled() bool { return true }

func TestScriptDNSQueryAutoUsesTheCoresResolverAndItsCache(t *testing.T) {
	stub := startScriptDNSUDP(t, 0, false)
	previousResolver, previousMapper := resolver.DefaultResolver, resolver.DefaultHostMapper
	resolver.DefaultResolver = dns.NewResolver(dns.Config{Main: []dns.NameServer{{Net: "udp", Addr: stub.addr}}, IPv6: true})
	resolver.DefaultHostMapper = fakeIPMapper{}
	t.Cleanup(func() { resolver.DefaultResolver, resolver.DefaultHostMapper = previousResolver, previousMapper })

	first := askScriptDNS(t, map[string]any{"domain": "example.com", "protocol": "auto"})
	if first.Error != nil {
		t.Fatalf("%s: %s", first.Error.Code, first.Error.Message)
	}
	if got := strings.Join(first.values(), ", "); got != "A 192.0.2.1, AAAA 2001:db8::1" || first.Protocol != "auto" || first.Server != "" || first.FromCache {
		t.Fatalf("auto's first answer: %+v", first)
	}
	asked := stub.hits.Load()
	second := askScriptDNS(t, map[string]any{"domain": "example.com"})
	if second.Error != nil || !second.FromCache || stub.hits.Load() != asked {
		t.Fatalf("auto's second answer must come from the cache: %+v (server asked %d more times)", second, stub.hits.Load()-asked)
	}
}

func TestScriptDNSQueryRouteAnswersWithTheExportsJSON(t *testing.T) {
	previousResolver := resolver.DefaultResolver
	resolver.DefaultResolver = nil
	t.Cleanup(func() { resolver.DefaultResolver = previousResolver })

	request := mhttptest.NewRequest("POST", "/clash/v1/dns/script-query", strings.NewReader(`{"domain":"example.com"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := mhttptest.NewRecorder()
	serveScriptDNSQuery(recorder, request)
	if recorder.Code != 200 || recorder.Body.String() != ScriptDNSQueryJSON(`{"domain":"example.com"}`) {
		t.Fatalf("status %d body %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"code":"UNAVAILABLE"`) {
		t.Fatalf("auto without a resolver: %s", recorder.Body.String())
	}

	request = mhttptest.NewRequest("POST", "/clash/v1/dns/script-query", strings.NewReader(`{"domain":"example.com"}`))
	recorder = mhttptest.NewRecorder()
	serveScriptDNSQuery(recorder, request)
	if recorder.Code != 415 {
		t.Fatalf("a body that is not declared JSON: status %d", recorder.Code)
	}
}

// The App's script runner reaches the route through the APIClient, as it reaches every other
// controller route: the request goes as the script wrote it, and the answer comes back as the
// export would give it, the core's own {"error"} included; only what never reached the core is
// an error.
func TestScriptDNSQueryClientAsksTheRouteAndAnswersAsTheExport(t *testing.T) {
	withScriptDNSCore(t, "MATCH,DIRECT")
	stub := startScriptDNSUDP(t, 0, false)
	path := shortClashSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	type seen struct{ line, contentType, body string }
	requests := make(chan seen, 8)
	server := &mhttp.Server{Handler: mhttp.HandlerFunc(func(writer mhttp.ResponseWriter, request *mhttp.Request) {
		body, _ := io.ReadAll(request.Body)
		requests <- seen{request.Method + " " + request.RequestURI, request.Header.Get("Content-Type"), string(body)}
		request.Body = io.NopCloser(strings.NewReader(string(body)))
		serveScriptDNSQuery(writer, request)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	client, err := NewAPIClient(path, newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}

	asked := `{"domain": "example.com", "protocol": "udp", "server": "` + stub.addr + `", "timeoutMilliseconds": 3000}`
	answer, err := client.ScriptDNSQuery(asked)
	if err != nil {
		t.Fatalf("ScriptDNSQuery: %v", err)
	}
	if want := ScriptDNSQueryJSON(asked); answer != want {
		t.Fatalf("the client's answer %q, the export's %q", answer, want)
	}
	if got := <-requests; got.line != "POST /clash/v1/dns/script-query" || got.contentType != "application/json" || got.body != asked {
		t.Fatalf("the request as the route saw it: %+v", got)
	}

	for _, refused := range []string{`not json`, `{"domain": ""}`, `{"domain": "example.com", "protocol": "smtp"}`} {
		answer, err := client.ScriptDNSQuery(refused)
		if err != nil {
			t.Fatalf("%s: the core's refusal came back as an error: %v", refused, err)
		}
		if want := ScriptDNSQueryJSON(refused); answer != want || !strings.Contains(answer, `"error":{"code":`) {
			t.Fatalf("%s: the client's answer %q, the export's %q", refused, answer, want)
		}
		<-requests
	}

	if _, err := client.ScriptDNSQuery(`{"domain": "` + strings.Repeat("a", scriptDNSRequestLimit) + `"}`); err == nil {
		t.Fatal("a request past 4096 bytes was answered")
	}
	select {
	case got := <-requests:
		t.Fatalf("a request past the limit reached the route: %s", got.line)
	default:
	}

	unreachable, err := NewAPIClient(shortClashSocketPath(t), newRecordingClashAPIHandler())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unreachable.ScriptDNSQuery(asked); err == nil {
		t.Fatal("a query with no controller to ask was answered")
	}
}
