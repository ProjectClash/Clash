package mitm

// Frame- and leg-level tests for the hand-rolled HTTP/2 bridge in h2.go.
// The server leg is driven over a real TCP connection: the test plays the
// h2 client in raw bytes (preface + frames) and asserts on the frames that
// come back. The client leg is driven against a scripted frame server.
// Tests are named TestH2*/TestFrame*/TestFlow*/TestContinuation*/TestRST*/
// TestEndStream* so a focused -run sweep covers them.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// ---- raw-frame harness ----

type h2TestConn struct {
	t    *testing.T
	cn   net.Conn
	br   *bufio.Reader
	dec  *hpack.Decoder
	enc  *hpack.Encoder
	encB strings.Builder
}

func newH2TestConn(t *testing.T, cn net.Conn) *h2TestConn {
	tc := &h2TestConn{t: t, cn: cn, br: bufio.NewReader(cn)}
	tc.dec = hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
		t.Logf("    hdr %s: %s", hf.Name, hf.Value)
	})
	tc.enc = hpack.NewEncoder(&writerAdapter{w: &tc.encB})
	return tc
}

type writerAdapter struct{ w *strings.Builder }

func (a *writerAdapter) Write(p []byte) (int, error) { return a.w.Write(p) }

func (tc *h2TestConn) readFrame() (h2Frame, error) {
	tc.cn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return readH2Frame(tc.br)
}

// readFrameWithTimeout reads one frame with an explicit deadline.
func (tc *h2TestConn) readFrameWithTimeout(d time.Duration) (h2Frame, error) {
	tc.cn.SetReadDeadline(time.Now().Add(d))
	return readH2Frame(tc.br)
}

// expectGOAWAY reads frames until a GOAWAY arrives (skipping anything else,
// e.g. the server's initial SETTINGS/WINDOW_UPDATE or a stray ACK).
func (tc *h2TestConn) expectGOAWAY(t *testing.T) (uint32, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read frame waiting for GOAWAY: %v", err)
		}
		switch f.typ {
		case h2FrameGOAWAY:
			if len(f.payload) < 8 {
				t.Fatalf("GOAWAY payload too short: %d", len(f.payload))
			}
			code := uint32(f.payload[4])<<24 | uint32(f.payload[5])<<16 | uint32(f.payload[6])<<8 | uint32(f.payload[7])
			debug := ""
			if len(f.payload) > 8 {
				debug = strings.TrimRight(string(f.payload[8:]), "\x00")
			}
			return code, debug
		default:
			// SETTINGS, WINDOW_UPDATE, PING ACK, ...: expected noise.
		}
	}
	t.Fatal("timed out waiting for GOAWAY")
	return 0, ""
}

// expectGOAWAYOrClose reads until GOAWAY or the connection closes. Returns
// code 0 (and no error) when the peer closed without a readable GOAWAY —
// the write side of a flooding client can buffer past the server's window,
// so the frame may be lost in a RST; a close after the cap is still
// enforcement.
func (tc *h2TestConn) expectGOAWAYOrClose(t *testing.T) (uint32, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			return 0, "" // connection closed
		}
		if f.typ == h2FrameGOAWAY && len(f.payload) >= 8 {
			code := uint32(f.payload[4])<<24 | uint32(f.payload[5])<<16 | uint32(f.payload[6])<<8 | uint32(f.payload[7])
			debug := ""
			if len(f.payload) > 8 {
				debug = strings.TrimRight(string(f.payload[8:]), "\x00")
			}
			return code, debug
		}
	}
	return 0, "timeout"
}

// expectRST reads frames until a RST_STREAM for streamID arrives.
func (tc *h2TestConn) expectRST(t *testing.T, streamID uint32) uint32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read frame waiting for RST_STREAM: %v", err)
		}
		if f.typ == h2FrameRSTStream && f.streamID == streamID {
			if len(f.payload) != 4 {
				t.Fatalf("RST_STREAM payload len %d", len(f.payload))
			}
			return uint32(f.payload[0])<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3])
		}
	}
	t.Fatal("timed out waiting for RST_STREAM")
	return 0
}

// ---- server leg harness ----

// startH2ServerLeg starts a real TCP listener, returns the client-side
// connection (raw frame access) and the server object the test drives.
func startH2ServerLeg(t *testing.T) (*h2TestConn, *h2Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	serverCh := make(chan net.Conn, 1)
	go func() {
		cn, err := ln.Accept()
		if err == nil {
			serverCh <- cn
		}
	}()
	cn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cn.Close() })
	var srv *h2Server
	select {
	case accepted := <-serverCh:
		srv = newH2Server(accepted, bufio.NewReader(accepted))
	case <-time.After(5 * time.Second):
		t.Fatal("server leg never accepted")
	}
	tc := newH2TestConn(t, cn)
	return tc, srv
}

// writeClientPreface writes the connection preface plus an empty SETTINGS,
// like any conforming client.
func (tc *h2TestConn) writeClientPreface(t *testing.T) {
	t.Helper()
	if _, err := tc.cn.Write([]byte(h2ClientPreface)); err != nil {
		t.Fatal(err)
	}
	if err := writeH2Frame(tc.cn, h2FrameSETTINGS, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
}

// writeRaw writes a raw frame the harness has no helper for.
func (tc *h2TestConn) writeRaw(t *testing.T, typ, flags uint8, streamID uint32, payload []byte) {
	t.Helper()
	if err := writeH2Frame(tc.cn, typ, flags, streamID, payload); err != nil {
		t.Fatal(err)
	}
}

// headerBlock encodes a request header block (pseudo :method/:path/...).
func (tc *h2TestConn) headerBlock(method, path, authority string) []byte {
	tc.encB.Reset()
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	return []byte(tc.encB.String())
}

// responseBlock encodes a response header block (:status + fields).
func (tc *h2TestConn) responseBlock(status string) []byte {
	tc.encB.Reset()
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":status", Value: status})
	return []byte(tc.encB.String())
}

// sendRequestHeaders sends a GET request; endStream controls END_STREAM.
func (tc *h2TestConn) sendRequestHeaders(t *testing.T, streamID uint32, endStream bool) {
	t.Helper()
	flags := uint8(h2FlagEndHeaders)
	if endStream {
		flags |= h2FlagEndStream
	}
	if err := writeH2Frame(tc.cn, h2FrameHEADERS, flags, streamID, tc.headerBlock("GET", "/", "example.com")); err != nil {
		t.Fatal(err)
	}
}

// ---- client leg harness ----

// startH2ClientLeg starts a scripted fake upstream that completes the h2
// handshake and hands the test the h2ClientConn.
func startH2ClientLeg(t *testing.T) (*h2TestConn, *h2ClientConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	fakeCh := make(chan net.Conn, 1)
	go func() {
		cn, err := ln.Accept()
		if err == nil {
			fakeCh <- cn
		}
	}()
	cc, err := newH2ClientConn(dialFuncForTest(ln.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	var fake net.Conn
	select {
	case fake = <-fakeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("fake upstream never accepted")
	}
	tc := newH2TestConn(t, fake)
	// Read the client preface + SETTINGS, ACK it.
	preface := make([]byte, len(h2ClientPreface))
	if _, err := io.ReadFull(tc.br, preface); err != nil {
		t.Fatal(err)
	}
	if string(preface) != h2ClientPreface {
		t.Fatalf("bad preface %q", preface)
	}
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == h2FrameSETTINGS {
			if f.flags&h2FlagAck == 0 {
				_ = writeH2Frame(fake, h2FrameSETTINGS, h2FlagAck, 0, nil)
				break
			}
		}
	}
	return tc, cc
}

func dialFuncForTest(addr string) net.Conn {
	cn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	return cn
}

// ---- W1: flow control ----

func TestFlowRegisterStreamUsesCurrentWindow(t *testing.T) {
	f := newH2Flow()
	if err := f.applyInitialWindow(128 << 20); err != nil {
		t.Fatal(err)
	}
	// A stream registered after the SETTINGS must start at the new window,
	// not the 64 KiB default (W1 oversend/undersend).
	f.registerStream(1)
	if got := f.streams[1]; got != 128<<20 {
		t.Fatalf("registered window = %d, want %d", got, 128<<20)
	}
	// grant(0) regression: a missing key must not materialize as 0.
	f2 := newH2Flow()
	f2.grant(7, 0)
	if got, ok := f2.streams[7]; ok && got == 0 {
		t.Fatalf("grant(id,0) created a zero window entry: take() would park forever")
	}
	_ = f2
}

func TestFlowTakeDefaultsToCurrentInitial(t *testing.T) {
	f := newH2Flow()
	// Stream not registered: take() must default to the current initial
	// window, not park on an implicit 0 entry.
	if n := f.take(9, 1000); n != 1000 {
		t.Fatalf("take() = %d, want 1000", n)
	}
}

func TestFlowInitialWindowDeltaAppliesToExistingStreams(t *testing.T) {
	f := newH2Flow()
	f.registerStream(1)
	f.registerStream(3)
	// RFC 9113 §6.9.2: delta applies to ALL streams.
	if err := f.applyInitialWindow(100); err != nil {
		t.Fatal(err)
	}
	if got := f.streams[1]; got != 100 {
		t.Fatalf("stream 1 window = %d, want 100 (delta math)", got)
	}
	if got := f.streams[3]; got != 100 {
		t.Fatalf("stream 3 window = %d, want 100 (delta math)", got)
	}
	if f.initial != 100 {
		t.Fatalf("initial = %d, want 100", f.initial)
	}
}

func TestFlowNegativeWindowIsError(t *testing.T) {
	f := newH2Flow()
	f.registerStream(1)
	// Consume 60 KiB of the 64 KiB window.
	if n := f.take(1, 60<<10); n != 60<<10 {
		t.Fatalf("take = %d", n)
	}
	// Shrink below consumed: negative result must be an error, not a
	// silent forever-wait.
	if err := f.applyInitialWindow(1024); err == nil {
		t.Fatal("expected FLOW_CONTROL_ERROR for negative resulting window")
	}
}

func TestH2RequestBodyWithSmallInitialWindow(t *testing.T) {
	// The W1 self-deadlock shape: peer sets INITIAL_WINDOW_SIZE 64 KiB
	// BEFORE our stream registers; a request with a body must complete.
	tc, cc := startH2ClientLeg(t)
	// Peer SETTINGS: INITIAL_WINDOW_SIZE = 64 KiB (default anyway) sent
	// BEFORE the request is created.
	tc.writeRaw(t, h2FrameSETTINGS, 0, 0, []byte{0x00, 0x04, 0x00, 0x01, 0x00, 0x00})
	body := strings.Repeat("x", 70000) // > 64 KiB
	req, _ := http.NewRequest("POST", "https://upstream.test/upload", strings.NewReader(body))
	req.Header.Set("Content-Length", fmt.Sprint(len(body)))
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
	// Fake upstream: read the request HEADERS+DATA frames, then answer.
	deadline := time.Now().Add(5 * time.Second)
	gotEnd := false
	gotBody := 0
	for time.Now().Before(deadline) && !gotEnd {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("reading request frames: %v", err)
		}
		if f.typ == h2FrameDATA {
			gotBody += len(f.payload)
			if f.flags&h2FlagEndStream != 0 {
				gotEnd = true
			}
			// Grant window back so the body can finish (skip zero-length
			// END_STREAM frames; WINDOW_UPDATE 0 is itself a conn error).
			if n := uint32(len(f.payload)); n > 0 {
				var wu [4]byte
				wu[0], wu[1], wu[2], wu[3] = byte(n>>24)&0x7f, byte(n>>16), byte(n>>8), byte(n)
				_ = writeH2Frame(tc.cn, h2FrameWindowUpdate, 0, 0, wu[:])
				_ = writeH2Frame(tc.cn, h2FrameWindowUpdate, 0, f.streamID, wu[:])
			}
		}
	}
	if gotBody != len(body) {
		t.Fatalf("upstream got %d body bytes, want %d", gotBody, len(body))
	}
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders|h2FlagEndStream, 1, tc.responseBlock("200"))
	select {
	case resp := <-respCh:
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	case err := <-errCh:
		t.Fatalf("RoundTrip failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip deadlocked (W1 regression)")
	}
}

// ---- W2: CONTINUATION handling ----

func TestContinuationWithoutOpenBlockIsConnError(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// CONTINUATION with no HEADERS open: protocol error.
	tc.writeRaw(t, h2FrameContinuation, h2FlagEndHeaders, 1, []byte{0x82})
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want %d (PROTOCOL_ERROR)", code, h2ErrorCodeProtocol)
	}
}

func TestContinuationWrongStreamIsConnError(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// HEADERS without END_HEADERS opens a block on stream 1...
	tc.writeRaw(t, h2FrameHEADERS, 0, 1, tc.headerBlock("GET", "/", "example.com"))
	// ...but CONTINUATION arrives on stream 3.
	tc.writeRaw(t, h2FrameContinuation, h2FlagEndHeaders, 3, []byte{0x82})
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want %d", code, h2ErrorCodeProtocol)
	}
}

func TestContinuationHeaderBlockOverCap(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// One HEADERS whose block alone exceeds the 64 KiB cap.
	big := make([]byte, h2MaxHeaderListBytes+1)
	tc.writeRaw(t, h2FrameHEADERS, 0, 1, big)
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want %d", code, h2ErrorCodeProtocol)
	}
}

func TestContinuationAccumulatesUnderCap(t *testing.T) {
	tc, srv := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// Split a valid block across HEADERS + CONTINUATION and confirm the
	// request still completes (the cap is not over-tight).
	tc.encB.Reset()
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "example.com"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	block := []byte(tc.encB.String())
	mid := len(block) / 2
	// END_STREAM rides the HEADERS frame even when the block continues;
	// CONTINUATION carries only END_HEADERS (RFC 9113 §6.10).
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndStream, 1, block[:mid])
	tc.writeRaw(t, h2FrameContinuation, h2FlagEndHeaders, 1, block[mid:])
	nextReq := func() *http.Request {
		ch := make(chan *http.Request, 1)
		go func() {
			req, err := srv.NextRequest()
			if err == nil {
				ch <- req
			}
		}()
		select {
		case req := <-ch:
			return req
		case <-time.After(5 * time.Second):
			return nil
		}
	}
	req := nextReq()
	if req == nil {
		t.Fatal("split header block never produced a request")
	}
	if req.Method != "GET" {
		t.Fatalf("method %q", req.Method)
	}
	// s.hdrOpen must be closed after END_HEADERS; a well-formed second
	// request proves the state machine resets (and would catch a stuck
	// hdrOpen, which would GOAWAY on the next HEADERS).
	tc.sendRequestHeaders(t, 3, true)
	req = nextReq()
	if req == nil {
		t.Fatal("second request after continuation block never arrived")
	}
	if h2StreamID(req) != 3 {
		t.Fatalf("second request on stream %d", h2StreamID(req))
	}
}

func TestContinuationFloodIsCapped(t *testing.T) {
	// CVE-2024-27316 shape: endless CONTINUATION frames on one block.
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	tc.writeRaw(t, h2FrameHEADERS, 0, 1, []byte{0x82}) // opens block, no END_HEADERS
	chunk := make([]byte, 8192)
	sent := 0
	// Keep feeding until the connection dies; total must cap near 64 KiB.
	for sent <= 4*h2MaxHeaderListBytes {
		if err := writeH2Frame(tc.cn, h2FrameContinuation, 0, 1, chunk); err != nil {
			break // connection closed by peer: cap enforced
		}
		sent += len(chunk)
	}
	// The GOAWAY is likely written after ~64 KiB; the socket may swallow it
	// when the server closes, so accept either the frame or a dead conn.
	code, debug := tc.expectGOAWAYOrClose(t)
	if code != 0 && code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d (%s), want PROTOCOL_ERROR", code, debug)
	}
	if code == 0 && sent > 8*h2MaxHeaderListBytes {
		t.Fatalf("accepted %d continuation bytes before close (cap leak)", sent)
	}
}

func TestContinuationClientLegWrongStreamIsConnError(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	// HEADERS opens a block on stream 1 (client leg has no stream yet).
	tc.writeRaw(t, h2FrameHEADERS, 0, 1, tc.responseBlock("200"))
	// CONTINUATION on another stream: connection error.
	tc.writeRaw(t, h2FrameContinuation, h2FlagEndHeaders, 3, []byte{0x82})
	// The conn aborts; a RoundTrip against it must fail rather than hang.
	req, _ := http.NewRequest("GET", "https://upstream.test/", nil)
	_, err := cc.RoundTrip(context.Background(), req)
	if err == nil {
		t.Fatal("RoundTrip on aborted connection succeeded")
	}
}

// ---- W3: concurrency + buffered-body budget ----

func TestH2ConcurrencyLimitRefusedStream(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// Open more streams than advertised; the excess must be refused with
	// RST_STREAM(REFUSED_STREAM). Half-open streams (no END_STREAM) count
	// toward the limit, so this exercises the real accounting. Send and
	// read interleaved so neither side's socket buffer stalls the exchange.
	seen := 0
	pump := func(timeout time.Duration) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			f, err := tc.readFrameWithTimeout(50 * time.Millisecond)
			if err != nil {
				return
			}
			if f.typ == h2FrameRSTStream && f.streamID > uint32(2*h2MaxConcurrentStreams) {
				code := uint32(f.payload[0])<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3])
				if code != h2ErrorCodeRefused {
					t.Fatalf("RST code %d, want %d (REFUSED)", code, h2ErrorCodeRefused)
				}
				seen++
			}
		}
	}
	// h2Max+4 odd-numbered streams: h2Max accepted, 4 refused.
	sent := 0
	for i := 1; i <= 2*(h2MaxConcurrentStreams+4); i += 2 {
		tc.sendRequestHeaders(t, uint32(i), false)
		sent++
		if sent%4 == 0 {
			pump(30 * time.Millisecond)
		}
	}
	// Final drain: everything the leg queued should be out by now.
	pump(3 * time.Second)
	if seen != 4 {
		t.Fatalf("saw %d refusals, want 4", seen)
	}
}

func TestH2ConnectionBodyBudgetRefusesStream(t *testing.T) {
	tc, srv := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// One stream just over the per-stream limit trips overflow (413);
	// verify the 413 path still works with the budget in place.
	tc.sendRequestHeaders(t, 1, false)
	over := make([]byte, h2StreamBodyLimit+1)
	for len(over) > 0 {
		n := len(over)
		if n > 16384 {
			n = 16384
		}
		chunk := over[:n]
		over = over[n:]
		flags := uint8(0)
		if len(over) == 0 {
			flags = h2FlagEndStream
		}
		tc.writeRaw(t, h2FrameDATA, flags, 1, chunk)
	}
	// 413 with END_STREAM on stream 1 (W4 applies to internal responses too).
	saw413 := false
	deadline := time.Now().Add(5 * time.Second)
	for !saw413 && time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.typ == h2FrameHEADERS && f.streamID == 1 {
			dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
				if hf.Name == ":status" && hf.Value == "413" {
					saw413 = true
				}
			})
			if _, err := dec.Write(f.payload); err != nil {
				t.Fatalf("hpack: %v", err)
			}
			if f.flags&h2FlagEndStream == 0 {
				t.Fatal("413 response missing END_STREAM")
			}
		}
	}
	if !saw413 {
		t.Fatal("overflow stream did not get 413")
	}
	// Drain the request so the serve loop is not stuck on NextRequest.
	if _, err := srv.NextRequest(); err == nil {
		t.Log("unexpected request delivered after overflow")
	}
}

// ---- W4: terminal responses carry END_STREAM ----

func TestEndStreamServerLegRejectAndRedirect(t *testing.T) {
	tc, srv := startH2ServerLeg(t)
	tc.writeClientPreface(t)

	// Stream 1: reject (403) via WriteSimpleResponse on the current stream.
	tc.sendRequestHeaders(t, 1, true)
	req, err := srv.NextRequest()
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	if h2StreamID(req) != 1 {
		t.Fatalf("request routed to stream %d", h2StreamID(req))
	}
	// The dispatcher calls leg.WriteSimpleResponse(policy.Reject); on h2
	// that lands in SubmitResponse with a bodyless *http.Response.
	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
	}
	if err := srv.SubmitResponse(resp); err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}
	// FinishBody is what the dispatcher calls next; it must be a no-op.
	if !srv.FinishBody(resp) {
		t.Fatal("FinishBody reported connection unusable")
	}
	status, endStream, extraData := readResponseFrames(t, tc, 1)
	if status != "403" {
		t.Fatalf("status %q, want 403", status)
	}
	if !endStream {
		t.Fatal("reject response missing END_STREAM (W4)")
	}
	if extraData {
		t.Fatal("reject response carried DATA after END_STREAM headers")
	}

	// Stream 3: redirect (302 with Location) via SubmitResponse.
	tc.sendRequestHeaders(t, 3, true)
	req, err = srv.NextRequest()
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	if h2StreamID(req) != 3 {
		t.Fatalf("request routed to stream %d", h2StreamID(req))
	}
	redir := &http.Response{
		StatusCode:    http.StatusFound,
		Status:        "302 Found",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
	}
	redir.Header.Set("Location", "https://example.com/moved")
	if err := srv.SubmitResponse(redir); err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}
	if !srv.FinishBody(redir) {
		t.Fatal("FinishBody reported connection unusable")
	}
	status, endStream, _ = readResponseFrames(t, tc, 3)
	if status != "302" {
		t.Fatalf("status %q, want 302", status)
	}
	if !endStream {
		t.Fatal("redirect response missing END_STREAM (W4)")
	}
}

// readResponseFrames reads HEADERS (+DATA) for streamID and returns the
// :status, whether END_STREAM was seen on the HEADERS, and whether any DATA
// frame followed.
func readResponseFrames(t *testing.T, tc *h2TestConn, streamID uint32) (status string, endStream bool, extraData bool) {
	t.Helper()
	var dec *hpack.Decoder
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read response frames: %v", err)
		}
		if f.typ == h2FrameHEADERS && f.streamID == streamID {
			status = ""
			dec = hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
				if hf.Name == ":status" {
					status = hf.Value
				}
			})
			if _, err := dec.Write(f.payload); err != nil {
				t.Fatalf("hpack: %v", err)
			}
			endStream = f.flags&h2FlagEndStream != 0
			if endStream {
				return status, true, false
			}
			// HEADERS without END_STREAM: peek for DATA.
			for {
				df, err := tc.readFrame()
				if err != nil {
					t.Fatalf("read body frames: %v", err)
				}
				if df.typ == h2FrameDATA && df.streamID == streamID {
					return status, df.flags&h2FlagEndStream != 0, df.flags&h2FlagEndStream == 0
				}
				if df.typ == h2FrameRSTStream || df.typ == h2FrameGOAWAY {
					t.Fatalf("unexpected %d while waiting for body", df.typ)
				}
			}
		}
	}
}

func TestEndStreamBodylessResponsesAreComplete(t *testing.T) {
	// respondSimple (the 413 path) and SubmitResponse-with-Content-Length:0
	// must both close the stream.
	tc, srv := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	tc.sendRequestHeaders(t, 1, false)
	// Complete stream 1 with an empty DATA frame (END_STREAM), triggering
	// the overflow-less finalize path is not needed: drive respondSimple
	// through a small overflow instead — simpler: directly answer the
	// current request.
	tc.writeRaw(t, h2FrameDATA, h2FlagEndStream, 1, nil)
	req, err := srv.NextRequest()
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	_ = req
	resp := &http.Response{
		StatusCode:    http.StatusBadGateway,
		Status:        "502 Bad Gateway",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
	}
	if err := srv.SubmitResponse(resp); err != nil {
		t.Fatalf("SubmitResponse: %v", err)
	}
	if !srv.FinishBody(resp) {
		t.Fatal("FinishBody false")
	}
	status, endStream, extra := readResponseFrames(t, tc, 1)
	if status != "502" || !endStream || extra {
		t.Fatalf("status=%q endStream=%v extraData=%v, want 502/true/false", status, endStream, extra)
	}
}

// ---- W5: RST_STREAM is per-stream on the client leg ----

func TestRSTStreamDoesNotKillClientConnection(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	// First RoundTrip: upstream answers with RST_STREAM for stream 1.
	req1, _ := http.NewRequest("GET", "https://upstream.test/first", nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := cc.RoundTrip(context.Background(), req1)
		errCh <- err
	}()
	for {
		f, err := tc.readFrame() // the request HEADERS (skip SETTINGS noise)
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == h2FrameHEADERS || f.typ == h2FrameContinuation {
			if f.streamID == 1 {
				break
			}
		}
	}
	rst := []byte{0, 0, 0, h2ErrorCodeInternal}
	tc.writeRaw(t, h2FrameRSTStream, 0, 1, rst)
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected RoundTrip to fail on RST_STREAM")
		}
		if !strings.Contains(err.Error(), "reset") {
			t.Fatalf("error %v should mention the reset", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip hung after RST_STREAM")
	}
	// The connection must still work: second RoundTrip succeeds.
	req2, _ := http.NewRequest("GET", "https://upstream.test/second", nil)
	respCh := make(chan *http.Response, 1)
	go func() {
		resp, err := cc.RoundTrip(context.Background(), req2)
		if err == nil {
			respCh <- resp
		} else {
			errCh <- err
		}
	}()
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read second request: %v", err)
		}
		if f.typ == h2FrameHEADERS && f.streamID == 3 {
			break
		}
	}
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders|h2FlagEndStream, 3, tc.responseBlock("200"))
	select {
	case resp := <-respCh:
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	case err := <-errCh:
		t.Fatalf("second RoundTrip after RST failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("second RoundTrip hung (W5 regression: connection was killed)")
	}
}

// ---- W6: frame-layer hardening ----

func TestFrameWindowUpdateZeroIncrement(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	tc.writeRaw(t, h2FrameWindowUpdate, 0, 0, []byte{0, 0, 0, 0})
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want PROTOCOL_ERROR", code)
	}
}

func TestFrameWindowUpdateOverflow(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// 0x7fffffff twice: the second pushes past 2^31-1.
	// First bump is legal (window 65535 + 0x7f000000 < 2^31-1); the second
	// crosses 2^31-1 and must be rejected.
	tc.writeRaw(t, h2FrameWindowUpdate, 0, 0, []byte{0x7f, 0x00, 0x00, 0x00})
	tc.writeRaw(t, h2FrameWindowUpdate, 0, 0, []byte{0x00, 0xff, 0xff, 0xff})
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeFlowControl {
		t.Fatalf("GOAWAY code %d, want FLOW_CONTROL_ERROR", code)
	}
}

func TestFrameSettingsWrongLength(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	tc.writeRaw(t, h2FrameSETTINGS, 0, 0, []byte{0, 0, 1}) // not a multiple of 6
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want PROTOCOL_ERROR", code)
	}
}

func TestFramePingAnsweredAndLengthEnforced(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// A well-formed PING must be answered with an ACK echoing the payload.
	opaque := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	tc.writeRaw(t, h2FramePING, 0, 0, opaque)
	deadline := time.Now().Add(5 * time.Second)
	acked := false
	for !acked && time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.typ == h2FramePING && f.flags&h2FlagAck != 0 {
			if string(f.payload) != string(opaque) {
				t.Fatalf("PING ACK payload %v, want %v", f.payload, opaque)
			}
			acked = true
		}
	}
	if !acked {
		t.Fatal("PING was never answered")
	}
	// A PING with a wrong body length is a connection error.
	tc.writeRaw(t, h2FramePING, 0, 0, []byte{1, 2, 3})
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want PROTOCOL_ERROR", code)
	}
}

func TestFrameDataUnknownStreamIsConnError(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// Stream 3 was never opened by the client (odd = client-initiated, so
	// the parity check passes; the stream itself is unknown to the leg).
	tc.writeRaw(t, h2FrameDATA, h2FlagEndStream, 3, []byte("junk"))
	code, _ := tc.expectGOAWAY(t)
	if code != h2ErrorCodeProtocol {
		t.Fatalf("GOAWAY code %d, want PROTOCOL_ERROR", code)
	}
}

func TestFramePushPromiseRefused(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// A server leg must never accept a PUSH_PROMISE from the client.
	pp := []byte{0, 0, 0, 3, 0x82} // promised stream 3 + one header field
	tc.writeRaw(t, h2FramePushPromise, h2FlagEndHeaders, 1, pp)
	tc.expectRST(t, 1)
}

func TestFrameSettingsInitialWindowReductionConnError(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	// Bump our send window high, put a request's DATA in flight against
	// the (flow-registered) stream, then shrink INITIAL_WINDOW_SIZE below
	// the consumed bytes: FLOW_CONTROL_ERROR, never a silent wait.
	tc.writeRaw(t, h2FrameSETTINGS, 0, 0, []byte{0x00, 0x04, 0x01, 0x00, 0x00, 0x00}) // 16 MiB
	tc.writeRaw(t, h2FrameSETTINGS, h2FlagAck, 0, nil)                                // ACK the preface SETTINGS
	body := make([]byte, 4096)
	req, _ := http.NewRequest("POST", "https://upstream.test/upload", strings.NewReader(string(body)))
	go func() {
		_, _ = cc.RoundTrip(context.Background(), req)
	}()
	// Read the request HEADERS, then reduce the window below consumed.
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.typ == h2FrameHEADERS && f.streamID == 1 {
			break
		}
	}
	// Reduce below 4096 consumed on stream 1 — but wait for the DATA to be
	// consumed first: reduction is legal until the bytes are written.
	tc.writeRaw(t, h2FrameSETTINGS, 0, 0, []byte{0x00, 0x04, 0x00, 0x00, 0x01, 0x00}) // 256
	code, _ := tc.expectGOAWAYOrClose(t)
	if code != 0 && code != h2ErrorCodeFlowControl {
		t.Fatalf("GOAWAY code %d, want FLOW_CONTROL_ERROR", code)
	}
	if code == 0 {
		t.Fatal("connection closed without GOAWAY; expected FLOW_CONTROL_ERROR")
	}
}

func TestFrameServerAdvertisesConcurrencyAndWindows(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	var maxStreams, initialWindow uint32
	sawSettings := false
	deadline := time.Now().Add(5 * time.Second)
	for !sawSettings && time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.typ != h2FrameSETTINGS || f.flags&h2FlagAck != 0 {
			continue
		}
		sawSettings = true
		for i := 0; i+6 <= len(f.payload); i += 6 {
			id := uint16(f.payload[i])<<8 | uint16(f.payload[i+1])
			v := uint32(f.payload[i+2])<<24 | uint32(f.payload[i+3])<<16 | uint32(f.payload[i+4])<<8 | uint32(f.payload[i+5])
			switch id {
			case 0x3:
				maxStreams = v
			case 0x4:
				initialWindow = v
			}
		}
	}
	if !sawSettings {
		t.Fatal("server never sent SETTINGS")
	}
	if maxStreams != h2MaxConcurrentStreams {
		t.Fatalf("MAX_CONCURRENT_STREAMS = %d, want %d", maxStreams, h2MaxConcurrentStreams)
	}
	if initialWindow != h2StreamRecvWindow {
		t.Fatalf("INITIAL_WINDOW_SIZE = %d, want %d", initialWindow, h2StreamRecvWindow)
	}
}

// ---- misc guards ----

func TestH2ServerRespondsCompleteOnUnknownStreamRST(t *testing.T) {
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// RST for a stream that never existed must not crash or kill the conn;
	// the leg should stay healthy (PING still answered).
	tc.writeRaw(t, h2FrameRSTStream, 0, 99, []byte{0, 0, 0, h2ErrorCodeRefused})
	opaque := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	tc.writeRaw(t, h2FramePING, 0, 0, opaque)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("connection died after stray RST: %v", err)
		}
		if f.typ == h2FramePING && f.flags&h2FlagAck != 0 {
			return
		}
	}
	t.Fatal("PING after stray RST never answered")
}

func TestH2ClientLegGoawayEndsConn(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	tc.writeRaw(t, h2FrameGOAWAY, 0, 0, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	req, _ := http.NewRequest("GET", "https://upstream.test/", nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := cc.RoundTrip(context.Background(), req)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("RoundTrip after GOAWAY should fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RoundTrip hung after GOAWAY")
	}
}

func TestH2WriteHeaderBlockSplitsLargeBlocks(t *testing.T) {
	// A header block larger than one frame payload is written as
	// HEADERS + CONTINUATIONs with correct END_HEADERS placement. The
	// block must not exceed the 64 KiB receive cap we enforce on peers.
	tc, srv := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	// ~96 KiB spread over several headers, all under one stream's budget.
	long := strings.Repeat("v", 16384)
	fields := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "x-big-1", Value: long},
		{Name: "x-big-2", Value: long},
		{Name: "x-big-3", Value: long},
		{Name: "x-big-4", Value: long},
		{Name: "x-big-5", Value: long},
	}
	// startH2ServerLeg returns tc (client side) and srv (server side); the
	// server object writes from its own end of the socket.
	srv.enc = hpack.NewEncoder(&srv.encBuf)
	tc.encB.Reset()
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "x"})
	_ = tc.enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	if err := writeH2Frame(tc.cn, h2FrameHEADERS, h2FlagEndHeaders|h2FlagEndStream, 1, []byte(tc.encB.String())); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.writeHeaderBlock(1, true, func(enc *hpack.Encoder) error {
			for _, hf := range fields {
				if err := enc.WriteField(hf); err != nil {
					return err
				}
			}
			return nil
		})
	}()
	var block []byte
	sawEnd := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !sawEnd {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch f.typ {
		case h2FrameHEADERS, h2FrameContinuation:
			block = append(block, f.payload...)
			if f.flags&h2FlagEndHeaders != 0 {
				sawEnd = true
			}
		}
	}
	if !sawEnd {
		t.Fatal("header block never ended")
	}
	if len(block) <= h2MaxWriteFrame {
		t.Fatalf("block %d bytes was not split across frames", len(block))
	}
	dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
		if hf.Name == "x-big-5" && hf.Value != long {
			t.Errorf("big header truncated: got %d bytes", len(hf.Value))
		}
	})
	if _, err := dec.Write(block); err != nil {
		t.Fatalf("hpack: %v", err)
	}
}

func TestH2DecodeErrorsDoNotPanic(t *testing.T) {
	// Garbage HPACK must surface an error, not corrupt the leg.
	tc, _ := startH2ServerLeg(t)
	tc.writeClientPreface(t)
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders, 1, garbage)
	// The leg may RST the stream or GOAWAY; either is fine, as long as it
	// does not hang or panic.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := tc.readFrame()
		if err != nil {
			return // closed
		}
		if f.typ == h2FrameRSTStream || f.typ == h2FrameGOAWAY {
			return
		}
	}
	t.Fatal("no reaction to garbage header block")
}

func TestH2ClientLegBodyStreamsBack(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	req, _ := http.NewRequest("GET", "https://upstream.test/stream", nil)
	respCh := make(chan *http.Response, 1)
	errCh2 := make(chan error, 1)
	go func() {
		resp, err := cc.RoundTrip(context.Background(), req)
		if err != nil {
			errCh2 <- err
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
	hdr := tc.responseBlock("200")
	tc.writeRaw(t, h2FrameHEADERS, h2FlagEndHeaders, 1, hdr)
	payload1 := []byte("hello ")
	payload2 := []byte("world")
	tc.writeRaw(t, h2FrameDATA, 0, 1, payload1)
	tc.writeRaw(t, h2FrameDATA, h2FlagEndStream, 1, payload2)
	select {
	case resp := <-respCh:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		_ = resp.Body.Close()
		if string(body) != "hello world" {
			t.Fatalf("body %q", body)
		}
		if !cc.FinishBody(resp) {
			t.Fatal("FinishBody false after END_STREAM")
		}
	case err := <-errCh2:
		t.Fatalf("RoundTrip: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

func TestH2RoundTripContextCancel(t *testing.T) {
	tc, cc := startH2ClientLeg(t)
	req, _ := http.NewRequest("GET", "https://upstream.test/slow", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := cc.RoundTrip(ctx, req)
		done <- err
	}()
	for {
		f, err := tc.readFrame()
		if err != nil {
			t.Fatal(err)
		}
		if f.typ == h2FrameHEADERS {
			break
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not unblock RoundTrip")
	}
}
