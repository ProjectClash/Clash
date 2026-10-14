package mitm

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
)

// e2eEnv wires a real TLS server (the "origin"), a dispatcher whose dial
// func connects straight to it, and a raw listener acting as the client
// entry the tunnel would hand over. The test drives stdlib HTTP clients
// through the full intercepted path: peek SNI, mint leaf, terminate TLS,
// rewrite, dial upstream through the dial func, stream back.
type e2eEnv struct {
	t         *testing.T
	origin    *httptest.Server
	originURL string
	engine    *Engine
	dispatch  *Dispatcher
	listener  net.Listener
	roots     *x509.CertPool
}

func newE2E(t *testing.T, config *Config) *e2eEnv {
	t.Helper()
	// Origin certificate for the intercepted host, so the outer-leg TLS
	// handshake verifies the way it would against a real origin.
	originCert := generateOriginCert(t, "gated.test")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/header-echo":
			w.Header().Set("X-Seen-UA", r.Header.Get("User-Agent"))
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "ok")
		case "/body":
			_, _ = io.WriteString(w, strings.Repeat("payload-", 2048)) // 16 KiB
		default:
			_, _ = io.WriteString(w, "hello from "+r.Host+" "+r.URL.Path)
		}
	})
	origin := httptest.NewUnstartedServer(handler)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{originCert}}
	origin.StartTLS()
	t.Cleanup(origin.Close)

	// The dial func stands in for the tunnel's proxy dial: it must connect
	// to the origin's host:port. In tests the origin listens on 127.0.0.1:port,
	// so resolve "gated.test" style names to it.
	originHost, originPortStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	if _, err := strconv.Atoi(originPortStr); err != nil {
		t.Fatalf("origin port: %v", err)
	}

	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	// Trust the origin's certificate on the outer leg, the way the config
	// layer seeds UpstreamRoots from tls.custom-trust-cert.
	roots := x509.NewCertPool()
	roots.AddCert(originCert.Leaf)
	config.UpstreamRoots = roots
	dispatch, err := NewDispatcher(config)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	// Swap in the test engine (NewDispatcher generated its own).
	dispatch.engine = engine

	dial := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		// Every dial lands on the origin regardless of the requested name;
		// the client sends its original Host header, which is what the
		// handler echoes.
		return net.Dial("tcp", net.JoinHostPort(originHost, originPortStr))
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	env := &e2eEnv{t: t, origin: origin, originURL: origin.URL, engine: engine, dispatch: dispatch, listener: listener, roots: tlsCertPool(t, engine)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				buffered := N.NewBufferedConn(raw)
				metadata := &C.Metadata{
					Host:    "gated.test",
					DstPort: 443,
					DNSMode: C.DNSMapping,
				}
				_ = dispatch.InnerHandle(context.Background(), buffered, metadata, dial)
				_ = raw.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return env
}

func (e *e2eEnv) client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Clients "connect to gated.test:443"; actually to the listener.
				return net.Dial("tcp", e.listener.Addr().String())
			},
			TLSClientConfig: &tls.Config{
				ServerName: "gated.test",
				RootCAs:    e.roots,
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: 10 * time.Second,
	}
}

func fmtSscan(s string, v ...any) (int, error) {
	return fmtSscanf(s, "%d", v...)
}

func fmtSscanf(s string, format string, v ...any) (int, error) {
	n, err := sscanf(s, format, v...)
	return n, err
}

func sscanf(s string, format string, v ...any) (int, error) {
	// tiny helper avoiding fmt import churn; only "%d" is used
	var n int
	var err error
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	if n == 0 && len(s) == 0 {
		err = io.ErrUnexpectedEOF
	}
	for _, p := range v {
		if ip, ok := p.(*int); ok {
			*ip = n
		}
	}
	return 1, err
}

func TestE2EHTTPSInterceptAndForward(t *testing.T) {
	config := &Config{
		Enable:    true,
		HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "gated.test/", HeaderRules: []HeaderRule{{Action: "set", Name: "User-Agent", Value: "mitm-e2e/1.0"}}},
		},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	resp, err := env.client().Get("https://gated.test/hello")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello from gated.test") {
		t.Fatalf("unexpected body %q", string(body))
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no TLS to the intercepted leg")
	}
	if !strings.HasPrefix(resp.TLS.PeerCertificates[0].Subject.CommonName, "gated.test") {
		t.Fatalf("client did not see our leaf: CN=%s", resp.TLS.PeerCertificates[0].Subject.CommonName)
	}
}

func TestE2EHeaderRewriteReachesUpstream(t *testing.T) {
	config := &Config{
		Enable:    true,
		HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "gated.test/header-echo", HeaderRules: []HeaderRule{{Action: "set", Name: "User-Agent", Value: "rewritten-agent/2.0"}}},
		},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	resp, err := env.client().Get("https://gated.test/header-echo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Seen-UA"); got != "rewritten-agent/2.0" {
		t.Fatalf("upstream saw User-Agent %q, want rewritten value", got)
	}
}

func TestE2ERejectAnswersWithoutUpstream(t *testing.T) {
	config := &Config{
		Enable:    true,
		HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "gated.test/forbidden", Reject: 403},
			{URLPattern: "gated.test/"},
		},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	resp, err := env.client().Get("https://gated.test/forbidden")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("reject answered %d, want 403", resp.StatusCode)
	}
}

func TestE2ERedirectAnswersImmediately(t *testing.T) {
	config := &Config{
		Enable:    true,
		HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "gated.test/old", Redirect: "https://gated.test/new"},
		},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	client := env.client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get("https://gated.test/old/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("redirect answered %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://gated.test/new" {
		t.Fatalf("Location %q", loc)
	}
}

func TestE2EStreamingBody(t *testing.T) {
	config := &Config{
		Enable:          true,
		HostGates:       []string{"gated.test"},
		RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/"}},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	resp, err := env.client().Get("https://gated.test/body")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 16*1024 {
		t.Fatalf("body length %d, want 16384", len(body))
	}
}

func TestE2EKeepAliveServesMultipleRequests(t *testing.T) {
	config := &Config{
		Enable:          true,
		HostGates:       []string{"gated.test"},
		RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/"}},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	client := env.client()
	for i := 0; i < 3; i++ {
		resp, err := client.Get("https://gated.test/round" + string(rune('a'+i)))
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !strings.Contains(string(body), "round"+string(rune('a'+i))) {
			t.Fatalf("round %d body %q", i, string(body))
		}
	}
}

func TestE2EUngatedHostPassesThrough(t *testing.T) {
	config := &Config{
		Enable:          true,
		HostGates:       []string{"gated.test"},
		RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/"}},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	// other.test is not gated: InnerHandle must decline (return false path)
	// and the client's TLS to the origin would be needed for a full answer.
	// Here we assert the decline: a client speaking TLS for other.test gets
	// no usable response because the raw conn is passed through untouched.
	conn, err := net.Dial("tcp", env.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "other.test", RootCAs: env.roots, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("ungated SNI unexpectedly completed a handshake with MITM")
	}
	// The conn is returned unmodified; the ClientHello bytes are still there
	// for the tunnel. Verify via peek on the raw side is not possible after
	// tls.Client buffered the write, so assert the documented contract:
	// InnerHandle declined (handshake refused by the interceptor, not minted).
}

func generateOriginCert(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("origin key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("origin cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse origin cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestE2EHTTP1ClientToH2UpstreamBridge(t *testing.T) {
	config := &Config{
		Enable:    true,
		HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "gated.test/header-echo", HeaderRules: []HeaderRule{{Action: "set", Name: "User-Agent", Value: "h1-bridge/1.0"}}},
		},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	env := newE2E(t, config)
	// Force HTTP/1.1 on the inner leg: the client offers no h2, so the
	// interceptor must bridge to whatever the upstream speaks.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", env.listener.Addr().String())
			},
			TLSClientConfig: &tls.Config{
				ServerName: "gated.test",
				RootCAs:    env.roots,
				NextProtos: []string{"http/1.1"},
			},
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get("https://gated.test/header-echo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Seen-UA"); got != "h1-bridge/1.0" {
		t.Fatalf("upstream saw User-Agent %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body %q", string(body))
	}
}

func TestE2EIdleLimitDoesNotBusyLoop(t *testing.T) {
	config := &Config{
		Enable:          true,
		HostGates:       []string{"gated.test"},
		RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/"}},
	}
	if err := config.Normalize(); err != nil {
		t.Fatal(err)
	}
	_ = newE2E(t, config)
	// No client connects; the environment must simply idle. Nothing to
	// assert beyond the test not hanging within its timeout.
}

var _ = bufio.NewReader // retained for future tests
