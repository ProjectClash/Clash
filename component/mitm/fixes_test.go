package mitm

// Regression tests for the round-2 review fixes. Each test pins one defect
// that was reproduced against the pre-fix code:
//
//	R1  executor wiring          (integration, executor_test)
//	R2  WINDOW_UPDATE misroute   (TestFixWUReachesInFlightStream + big-body e2e)
//	R3  0-length RST panic       (TestFixZeroLengthRSTStream)
//	R4  s.active leak            (TestFixActiveCounterKeepsServingGETs)
//	R5  HPACK error -> GOAWAY    (TestFixHpackDecodeErrorIsConnectionError)
//	R6  server take deadline     (TestFixStalledClientReleasesServeLoop)
//	R7  SNI peek deadline        (TestFixPeekDeadlineReleasesStalledClient)
//	R8  HEADERS on stream 0/even (TestFixHeadersOnInvalidStreamID)
//	R9  effective port overlap   (TestFixEffectivePortOverlap)
//	R10 leaf/CA ownership        (TestFixLeafCacheOwnerAfterRegenerate)
//	R11 plain-HTTP gate w/o fake-ip (covered in e2e via DNSNormal metadata)

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
)

// --- R2: the stream-level WINDOW_UPDATE must land on the in-flight stream.

func TestFixWUReachesInFlightStream(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	req, _ := http.NewRequest("GET", "https://upstream.test/wu", nil)
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(context.Background(), req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == h2FrameHEADERS && f.streamID == 1 {
			break
		}
	}
	// Answer with response HEADERS (no END_STREAM) so RoundTrip returns.
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders, 1, tc.responseBlock("200"))
	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		t.Fatalf("RoundTrip: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no response headers")
	}
	// The response body rides an io.Pipe: the readLoop blocks writing into
	// it until someone reads, so a consumer MUST run before DATA flows or
	// the WINDOW_UPDATE frames (written after the pipe write) never leave.
	bodyDone := make(chan int, 1)
	go func() {
		n, _ := io.Copy(io.Discard, resp.Body)
		bodyDone <- int(n)
	}()
	// Feed 100 KiB in DATA frames; the leg must grant window back on
	// stream 1 or the upstream (a real peer) stalls at 65535.
	streamWU := int64(0)
	stopWU := make(chan struct{})
	wuDone := make(chan struct{})
	go func() {
		defer close(wuDone)
		for {
			select {
			case <-stopWU:
				return
			default:
			}
			tc.cn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			f, err := readH2Frame(tc.br)
			if err != nil {
				continue
			}
			if f.typ == h2FrameWindowUpdate && f.streamID == 1 {
				streamWU += int64(uint32(f.payload[0]&0x7f)<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3]))
			}
		}
	}()
	total := 100 << 10
	sent := 0
	for sent < total {
		n := 1 << 14
		if sent+n > total {
			n = total - sent
		}
		flags := uint8(0)
		if sent+n == total {
			flags = h2FlagEndStream
		}
		tc.cn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := writeH2Frame(tc.cn, h2FrameDATA, flags, 1, make([]byte, n)); err != nil {
			t.Fatalf("upstream stalled at %d/%d (window not replenished on stream 1)", sent, total)
		}
		sent += n
		// Interleave reads so both sockets keep draining: the WU watcher
		// runs concurrently, but give it a beat to keep the OS buffers
		// from swallowing frames we want to observe.
		if sent%(16<<10) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	close(stopWU)
	<-wuDone
	if streamWU == 0 {
		t.Fatal("no stream-level WINDOW_UPDATE reached stream 1")
	}
	// Signal END_STREAM so the body reader finishes.
	_ = writeH2Frame(tc.cn, h2FrameDATA, h2FlagEndStream, 1, nil)
	select {
	case n := <-bodyDone:
		if n != total {
			t.Fatalf("body consumed %d/%d bytes", n, total)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("body reader never finished")
	}
}

// R2 end-to-end: >64 KiB body through the full dispatcher bridge against a
// real Go h2 origin must arrive complete.
func TestFixBridgeH2UpstreamBigBody(t *testing.T) {
	body := strings.Repeat("B", 100<<10)
	env := newE2EH2UpstreamWithBody(t, body)
	resp, err := env.client().Get("https://gated.test/big")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	got, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if len(got) != len(body) {
		t.Fatalf("truncation: got %d/%d bytes", len(got), len(body))
	}
}

// newE2EH2UpstreamWithBody is newE2EH2Upstream (e2e_test.go) with a
// parameterizable body, so the big-body regression rides the real bridge.
func newE2EH2UpstreamWithBody(t *testing.T, body string) *e2eEnv {
	t.Helper()
	originCert := generateOriginCert(t, "gated.test")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	origin.TLS = &tls.Config{
		Certificates: []tls.Certificate{originCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)

	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	cfg := &Config{Enable: true, HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/"}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(originCert.Leaf)
	cfg.UpstreamRoots = roots
	dispatch, err := NewDispatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dispatch.engine = engine
	originHost, originPortStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	dial := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return net.Dial("tcp", net.JoinHostPort(originHost, originPortStr))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				bc := N.NewBufferedConn(raw)
				md := &C.Metadata{Host: "gated.test", DstPort: 443, DNSMode: C.DNSMapping}
				_ = dispatch.InnerHandle(context.Background(), bc, md, dial)
				_ = raw.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return &e2eEnv{t: t, origin: origin, engine: engine, dispatch: dispatch, listener: listener, roots: tlsCertPool(t, engine)}
}

// --- R3: a 0-length RST_STREAM must fail the round trip, not panic.

func TestFixZeroLengthRSTStream(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	req, _ := http.NewRequest("GET", "https://upstream.test/rst", nil)
	done := make(chan error, 1)
	go func() {
		_, err := cc.RoundTrip(context.Background(), req)
		done <- err
	}()
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == h2FrameHEADERS && f.streamID == 1 {
			break
		}
	}
	tc.writeRaw(t, h2FrameRSTStream, 0, 1, nil)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RoundTrip succeeded after RST_STREAM")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RoundTrip hung after empty RST_STREAM")
	}
	// A panicking readLoop would fail the whole test binary; reaching here
	// means the leg survived.
	time.Sleep(300 * time.Millisecond)
}

// --- R4: >h2MaxConcurrentStreams sequential GETs must all be served.

func TestFixActiveCounterKeepsServingGETs(t *testing.T) {
	tc, srv := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	for i := 1; i <= h2MaxConcurrentStreams*2+8; i++ {
		sid := uint32(i*2 - 1)
		tc.sendRequestHeaders(t, sid, true)
		served := make(chan struct{}, 1)
		go func() {
			req, err := srv.NextRequest()
			if err != nil {
				return
			}
			_ = srv.SubmitResponse(&http.Response{
				StatusCode: 200, Status: "200 OK",
				Proto: "HTTP/2.0", ProtoMajor: 2,
				Header:        make(http.Header),
				Body:          io.NopCloser(strings.NewReader("")),
				ContentLength: 0,
			})
			close(served)
			_ = req
		}()
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			t.Fatalf("request %d never delivered (active leak wedged the conn at %d)", i, h2MaxConcurrentStreams)
		}
		deadline := time.Now().Add(1 * time.Second)
	gotResp:
		for {
			tc.cn.SetReadDeadline(deadline)
			f, err := readH2Frame(tc.br)
			if err != nil {
				if time.Now().After(deadline) {
					t.Fatalf("request %d: no response (RST_STREAM(REFUSED)?)", i)
				}
				continue
			}
			switch f.typ {
			case h2FrameRSTStream:
				t.Fatalf("request %d refused: active counter still leaks", i)
			case h2FrameHEADERS:
				if f.flags&h2FlagEndHeaders != 0 {
					break gotResp
				}
			}
		}
	}
}

// --- R5: an undecodable header block must GOAWAY + close, not stay open.

func TestFixHpackDecodeErrorIsConnectionError(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders, 1, garbage)
	code, _ := tc.expectGOAWAYOrClose(t)
	if code == 0 {
		// Accept a bare close (the GOAWAY may be swallowed by RST), but the
		// connection MUST be dead either way.
		tc.cn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := readH2Frame(tc.br); err == nil {
			t.Fatal("connection still open after HPACK decode failure")
		}
		return
	}
	if code != h2ErrorCodeCompression {
		t.Fatalf("GOAWAY code %d, want COMPRESSION_ERROR (%d)", code, h2ErrorCodeCompression)
	}
}

// --- R6: a stalled h2 client must release the serve goroutine.

func TestFixStalledClientReleasesServeLoop(t *testing.T) {
	oldIdle := idleTimeout
	idleTimeout = 700 * time.Millisecond
	defer func() { idleTimeout = oldIdle }()

	tt, srv := startH2ServerLeg(t)
	tt.writeClientPreface(t)
	// Complete the request (END_HEADERS + END_STREAM on DATA) so it is
	// delivered, then stream a response larger than the advertised stream
	// window: the DATA writer must park on the window (never granted) and
	// be released by the per-chunk deadline instead of parking forever.
	tt.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders, 1, tt.headerBlock("POST", "/stall", "gated.test"))
	tt.writeRaw(t, h2FrameDATA, h2FlagEndStream, 1, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := srv.NextRequest()
		if err != nil {
			return
		}
		resp := &http.Response{
			StatusCode: 200, Status: "200 OK",
			Proto: "HTTP/2.0", ProtoMajor: 2,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 2<<20))),
			ContentLength: 2 << 20,
		}
		_ = srv.SubmitResponse(resp)
		srv.FinishBody(resp)
	}()
	select {
	case <-done:
		// The deadline released the writer (FinishBody false) or the
		// response fully fit the window; either way nothing is parked.
	case <-time.After(10 * time.Second):
		t.Fatal("serve goroutine parked forever on flow-control window")
	}
}

// --- R7: a stalled pre-ClientHello client must not pin the conn forever.

func TestFixPeekDeadlineReleasesStalledClient(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Enable: true, HostGates: []string{"gated.test"},
		RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/"}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	dispatch, err := NewDispatcher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dispatch.engine = engine
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	handled := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			handled <- false
			return
		}
		bc := N.NewBufferedConn(c)
		md := &C.Metadata{Host: "", DstPort: 443}
		handled <- dispatch.InnerHandle(context.Background(), bc, md, nil)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Connect, send NOTHING. The peek deadline must end the intercept.
	select {
	case <-handled:
		// The deadline expired, InnerHandle returned.
	case <-time.After(3 * innerHandshakeTimeout):
		t.Fatal("stalled client pinned the conn past the peek deadline")
	}
	_ = conn.Close()
}

// --- R8: HEADERS on stream 0 / even IDs must GOAWAY, not be answered.

func TestFixHeadersOnInvalidStreamID(t *testing.T) {
	for _, bad := range []uint32{0, 2, 4} {
		tc, _ := startH2ServerLeg(t)
		tc.writeClientPreface(t)
		tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders, bad, tc.headerBlock("GET", "/", "gated.test"))
		code, _ := tc.expectGOAWAY(t)
		if code != h2ErrorCodeProtocol {
			t.Fatalf("HEADERS on stream %d: GOAWAY code %d, want PROTOCOL_ERROR", bad, code)
		}
	}
}

// --- R9: effective port overlap.

func TestFixEffectivePortOverlap(t *testing.T) {
	// https-ports claims 80 with http standard-port-only: must reject.
	cfg := &Config{
		Enable:     true,
		HostGates:  []string{"a.com"},
		HTTPSPorts: portRanges(t, "80"),
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatal("https-ports:[80] with standard-port http must be rejected")
	}
	// http-ports claims 443 with https standard-port-only: must reject.
	cfg2 := &Config{
		Enable:     true,
		HostGates:  []string{"a.com"},
		HTTPPorts:  portRanges(t, "443"),
		RewritePolicies: []RewritePolicy{
			{URLPattern: "a.com/"},
		},
	}
	if err := cfg2.Normalize(); err == nil {
		t.Fatal("http-ports:[443] with standard-port https must be rejected")
	}
	// Disjoint effective sets still load.
	ok := &Config{
		Enable:     true,
		HostGates:  []string{"a.com"},
		HTTPSPorts: portRanges(t, "443"),
		HTTPPorts:  portRanges(t, "8080"),
		RewritePolicies: []RewritePolicy{
			{URLPattern: "a.com/"},
		},
	}
	if err := ok.Normalize(); err != nil {
		t.Fatalf("disjoint ports must parse: %v", err)
	}
}

// --- R10: leaves minted by a previous CA must not survive Regenerate.

func TestFixLeafCacheOwnerAfterRegenerate(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatal(err)
	}
	leaf, err := engine.MintLeaf("r.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot the OLD CA pair before the reset, so the race replay can
	// mint a genuine old-CA leaf.
	oldCert, oldKey := engine.caCert, engine.caKey
	if err := engine.Regenerate(); err != nil {
		t.Fatal(err)
	}
	// Replay the race: a mint that snapshotted the old CA inserts its leaf
	// after the reset. The ownership check must reject it.
	stale, err := mintLeaf(oldCert, oldKey, "race.example.com")
	if err != nil {
		t.Fatalf("mint stale leaf: %v", err)
	}
	engine.mu.Lock()
	engine.insertLeafLocked("race.example.com", stale)
	engine.mu.Unlock()

	// A read of the host must NOT serve the stale-CA leaf.
	after, err := engine.MintLeaf("race.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if after.Fingerprint == stale.Fingerprint {
		t.Fatal("stale-CA leaf was served after Regenerate")
	}
	if after.Certificate.Leaf == nil || !strings.HasSuffix(after.Certificate.Leaf.Subject.CommonName, "race.example.com") {
		t.Fatalf("unexpected replacement leaf: %+v", after.Certificate.Leaf)
	}
	// And the pre-reset cached leaf must also be refused by the ownership
	// check even though it is still time-fresh.
	engine.mu.Lock()
	owned := engine.leafOwnedLocked(leaf)
	engine.mu.Unlock()
	if owned {
		t.Fatal("leafOwnedLocked accepted a leaf minted by a previous CA")
	}
}

// --- R11: plain-HTTP gate on non-fake-ip metadata still intercepts.

func TestFixPlainHTTPGateWithoutDNSMapping(t *testing.T) {
	// Rely on the gate via the exported package API through an e2e-style
	// cleartext intercept whose metadata carries DNSNormal (what the
	// sniffer's replaceDomain leaves behind) and DNSFakeIP (default
	// enhanced mode).
	for _, mode := range []C.DNSMode{C.DNSNormal, C.DNSFakeIP} {
		cfg := &Config{
			Enable:          true,
			HostGates:       []string{"gated.test"},
			HTTPPorts:       portRanges(t, "80"),
			RewritePolicies: []RewritePolicy{{URLPattern: "gated.test/", Reject: 418}},
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatal(err)
		}
		engine := &Engine{leaves: make(map[string]*HostCertificate)}
		_ = engine.Regenerate()
		dispatch, err := NewDispatcher(cfg)
		if err != nil {
			t.Fatal(err)
		}
		dispatch.engine = engine
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		bc := N.NewBufferedConn(serverConn)
		md := &C.Metadata{Host: "gated.test", DstPort: 80, DNSMode: mode}
		go func() {
			_ = dispatch.InnerHandle(context.Background(), bc, md, nil)
		}()
		_, _ = clientConn.Write([]byte("GET /tea HTTP/1.1\r\nHost: gated.test\r\nConnection: close\r\n\r\n"))
		clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
		if err != nil {
			t.Fatalf("mode %v: no answer from the interceptor: %v", mode, err)
		}
		if resp.StatusCode != 418 {
			t.Fatalf("mode %v: status %d, want 418 (gate must intercept regardless of DNSMode)", mode, resp.StatusCode)
		}
	}
}
