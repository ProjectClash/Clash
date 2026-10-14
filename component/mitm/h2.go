package mitm

// Minimal HTTP/2 over one connection, both directions of the MITM bridge:
// the inner (client-facing) server leg and the outer (upstream) client leg.
// The frame layer and flow control are implemented here because the Apple
// SDK build must stay free of a full HTTP/2 stack; header compression uses
// golang.org/x/net/http2/hpack, which is already a direct dependency.
//
// Scope, deliberately narrow for interception use:
//   - no push promise, no trailers, no priorities beyond skipping them;
//   - one response at a time on the server leg (the serve loop is serial);
//   - request bodies buffer up to h2StreamBodyLimit, larger bodies are
//     answered 413 rather than streamed, keeping memory bounded (with an
//     h2ConnBodyBudget budget across the whole connection);
//   - connection-level flow control respected with wait-on-window for the
//     data we send, and WINDOW_UPDATEs issued for data we receive once it
//     has been consumed, so buffered bodies apply backpressure.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"
)

const (
	h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	h2FrameDATA         = 0x0
	h2FrameHEADERS      = 0x1
	h2FramePRIORITY     = 0x2
	h2FrameRSTStream    = 0x3
	h2FrameSETTINGS     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePING         = 0x6
	h2FrameGOAWAY       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	h2FlagAck        = 0x1
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	h2ErrorCodeFlowControl = 0x3
	h2ErrorCodeRefused     = 0x7
	h2ErrorCodeInternal    = 0x2
	h2ErrorCodeProtocol    = 0x1

	// We never emit a payload larger than the spec's default max frame size.
	h2MaxWriteFrame = 1 << 14
	// Request bodies buffer up to 1 MiB per stream; beyond that the stream is
	// refused with 413 instead of buffering without bound.
	h2StreamBodyLimit = 1 << 20
	// Total buffered request bodies across the connection: streams beyond
	// this budget are refused instead of buffering without bound.
	h2ConnBodyBudget = 8 << 20
	// Streams served concurrently; beyond it new streams are refused.
	h2MaxConcurrentStreams = 32
	// Connection-level receive window we advertise and grant.
	h2ConnRecvWindow = 1 << 30
	// Per-stream receive window we advertise.
	h2StreamRecvWindow = 1 << 20
	// Peer's initial send window per spec until their SETTINGS say otherwise.
	h2InitialSendWindow = 65535
	// Cap on one header block (HEADERS + CONTINUATION), x/net/http2 parity.
	h2MaxHeaderListBytes = 64 << 10

	h2HeaderTimeout = 15 * time.Second
)

type h2Frame struct {
	typ      uint8
	flags    uint8
	streamID uint32
	payload  []byte
}

func readH2Frame(br *bufio.Reader) (h2Frame, error) {
	var head [9]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return h2Frame{}, err
	}
	length := uint32(head[0])<<16 | uint32(head[1])<<8 | uint32(head[2])
	streamID := (uint32(head[5]&0x7f) << 24) | (uint32(head[6]) << 16) | (uint32(head[7]) << 8) | uint32(head[8])
	if length > 1<<20 {
		// Refuse absurd frames rather than buffering them; 1 MiB covers any
		// legitimate HEADERS block and our own SETTINGS.
		return h2Frame{}, fmt.Errorf("http2 frame too large (%d bytes)", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return h2Frame{}, err
	}
	return h2Frame{typ: head[3], flags: head[4], streamID: streamID, payload: payload}, nil
}

func writeH2Frame(w io.Writer, typ, flags uint8, streamID uint32, payload []byte) error {
	var head [9]byte
	n := len(payload)
	head[0], head[1], head[2] = byte(n>>16), byte(n>>8), byte(n)
	head[3], head[4] = typ, flags
	head[5], head[6], head[7], head[8] = byte(streamID>>24)&0x7f, byte(streamID>>16), byte(streamID>>8), byte(streamID)
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// h2Flow tracks the send windows a peer grants us, connection-level and
// per-stream, with a cond so DATA writers park until window exists.
//
// The current initial send window is a field of the flow (not a constant):
// SETTINGS_INITIAL_WINDOW_SIZE from the peer re-bases it with RFC 9113
// §6.9.2 delta math, so streams registered before and after a SETTINGS
// frame all see the same window.
type h2Flow struct {
	mu       sync.Mutex
	cond     *sync.Cond
	conn     int64
	streams  map[uint32]int64
	excluded map[uint32]bool // streams closed locally; stop waiting on them
	initial  int64           // current initial send window for new streams
}

func newH2Flow() *h2Flow {
	f := &h2Flow{conn: h2InitialSendWindow, streams: make(map[uint32]int64), excluded: make(map[uint32]bool), initial: h2InitialSendWindow}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *h2Flow) take(streamID uint32, max int64) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		if f.excluded[streamID] {
			return 0
		}
		connAvail := f.conn
		streamAvail, ok := f.streams[streamID]
		if !ok {
			streamAvail = f.initial
		}
		avail := connAvail
		if streamAvail < avail {
			avail = streamAvail
		}
		if avail > 0 {
			n := avail
			if n > max {
				n = max
			}
			f.conn -= n
			f.streams[streamID] = streamAvail - n
			return n
		}
		f.cond.Wait()
	}
}

// grant applies a WINDOW_UPDATE delta. A zero delta is a no-op (a
// stream grant on an unregistered stream must not materialize a zero
// window entry, which take() would honor and park on forever).
func (f *h2Flow) grant(streamID uint32, delta int64) {
	if delta == 0 {
		return
	}
	f.mu.Lock()
	if streamID == 0 {
		f.conn += delta
	} else {
		f.streams[streamID] += delta
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

// registerStream opens the stream's send window at the current initial
// window, so requests written before any peer SETTINGS adjust cleanly.
func (f *h2Flow) registerStream(streamID uint32) {
	f.mu.Lock()
	if _, ok := f.streams[streamID]; !ok {
		f.streams[streamID] = f.initial
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

// applyInitialWindow re-bases every stream window for a new
// SETTINGS_INITIAL_WINDOW_SIZE: RFC 9113 §6.9.2 says the delta applies to
// all streams, so existing entries shift by the delta and new streams start
// at the new value. A window driven negative by a reduction is a
// FLOW_CONTROL_ERROR per spec; the caller must treat the returned error as
// a connection error.
func (f *h2Flow) applyInitialWindow(value uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delta := int64(value) - f.initial
	// Validate first: a window driven negative by a reduction is a
	// FLOW_CONTROL_ERROR per RFC 9113 §6.9.2 and must not mutate state.
	for sid, w := range f.streams {
		if w+delta < 0 {
			return fmt.Errorf("http2: SETTINGS_INITIAL_WINDOW_SIZE drives stream %d window negative", sid)
		}
	}
	f.initial = int64(value)
	for sid, w := range f.streams {
		f.streams[sid] = w + delta
	}
	f.cond.Broadcast()
	return nil
}

func (f *h2Flow) exclude(streamID uint32) {
	f.mu.Lock()
	f.excluded[streamID] = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

// Shutdown excludes every stream and zeroes the connection window so parked
// DATA writers wake and fail instead of blocking on a dead connection.
func (f *h2Flow) Shutdown() {
	f.mu.Lock()
	f.conn = 0
	for sid := range f.streams {
		f.excluded[sid] = true
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

// ---- shared connection base ----

type h2Conn struct {
	conn   net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	enc    *hpack.Encoder
	encBuf bytes.Buffer

	flow *h2Flow

	// Header accumulation: CONTINUATION frames append until END_HEADERS,
	// then the block is decoded in one shot. hdrOpen records whether a
	// HEADERS block is being received; per RFC 9113 §4.3 a CONTINUATION
	// must continue the same stream with no interleaved frames, and the
	// total block size is capped at h2MaxHeaderListBytes.
	hdrBuf       []byte
	hdrStream    uint32
	hdrOpen      bool
	hdrEndStream bool // END_STREAM flag from the block-opening HEADERS
	dec          *hpack.Decoder
	pendingHdrs  *[]hpack.HeaderField

	writeErr atomic.Value // stored error, first write failure wins
}

func (c *h2Conn) onHeaderField(hf hpack.HeaderField) {
	if c.pendingHdrs != nil {
		*c.pendingHdrs = append(*c.pendingHdrs, hf)
	}
}

func (c *h2Conn) decodeHeaderBlock(payload []byte, streamID uint32) ([]hpack.HeaderField, error) {
	fields := make([]hpack.HeaderField, 0, 16)
	c.pendingHdrs = &fields
	defer func() { c.pendingHdrs = nil }()
	if _, err := c.dec.Write(payload); err != nil {
		return nil, err
	}
	return fields, nil
}

// writeFrames emits one logical frame, splitting payloads larger than the
// max frame size into DATA chunks. Header blocks that exceed the max must be
// split by the caller into HEADERS+CONTINUATION (see writeHeaderBlock).
func (c *h2Conn) writeFrame(typ, flags uint8, streamID uint32, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeFrameLocked(typ, flags, streamID, payload)
}

func (c *h2Conn) writeFrameLocked(typ, flags uint8, streamID uint32, payload []byte) error {
	if err := c.writeErr.Load(); err != nil {
		return err.(error)
	}
	if err := writeH2Frame(c.conn, typ, flags, streamID, payload); err != nil {
		c.writeErr.CompareAndSwap(nil, err)
		return err
	}
	return nil
}

// writeHeaderBlock writes HEADERS followed by CONTINUATION frames when the
// compressed block exceeds one frame payload.
func (c *h2Conn) writeHeaderBlock(streamID uint32, endStream bool, encode func(enc *hpack.Encoder) error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.encBuf.Reset()
	if err := encode(c.enc); err != nil {
		return err
	}
	block := c.encBuf.Bytes()
	first := block
	if len(first) > h2MaxWriteFrame {
		first = block[:h2MaxWriteFrame]
	}
	flags := uint8(0)
	if len(first) == len(block) {
		flags |= h2FlagEndHeaders
	}
	if endStream {
		flags |= h2FlagEndStream
	}
	if err := c.writeFrameLocked(h2FrameHEADERS, flags, streamID, first); err != nil {
		return err
	}
	rest := block[len(first):]
	for len(rest) > 0 {
		chunk := rest
		cflags := uint8(0)
		if len(chunk) > h2MaxWriteFrame {
			chunk = chunk[:h2MaxWriteFrame]
		} else {
			cflags |= h2FlagEndHeaders
		}
		if err := c.writeFrameLocked(h2FrameContinuation, cflags, streamID, chunk); err != nil {
			return err
		}
		rest = rest[len(chunk):]
	}
	return nil
}

func (c *h2Conn) writeDATA(streamID uint32, data []byte, endStream bool) error {
	for len(data) > 0 {
		want := int64(len(data))
		if want > h2MaxWriteFrame {
			want = h2MaxWriteFrame
		}
		n := c.flow.take(streamID, want)
		if n == 0 {
			return fmt.Errorf("http2 stream %d closed while writing", streamID)
		}
		chunk := data[:n]
		data = data[n:]
		flags := uint8(0)
		if len(data) == 0 && endStream {
			flags |= h2FlagEndStream
		}
		if err := c.writeFrame(h2FrameDATA, flags, streamID, chunk); err != nil {
			return err
		}
	}
	if len(data) == 0 && endStream {
		// zero-length body still needs the END_STREAM marker
		return c.writeFrame(h2FrameDATA, h2FlagEndStream, streamID, nil)
	}
	return nil
}

func (c *h2Conn) handleCommonFrame(f h2Frame) (bool, error) {
	switch f.typ {
	case h2FrameSETTINGS:
		if len(f.payload)%6 != 0 {
			return true, c.goawayConn(h2ErrorCodeProtocol, "settings frame length not a multiple of 6")
		}
		if f.flags&h2FlagAck == 0 {
			if err := c.applyPeerSettings(f.payload); err != nil {
				return true, c.goawayConn(h2ErrorCodeFlowControl, err.Error())
			}
			return true, c.writeFrame(h2FrameSETTINGS, h2FlagAck, 0, nil)
		}
		return true, nil
	case h2FramePING:
		if len(f.payload) != 8 {
			return true, c.goawayConn(h2ErrorCodeProtocol, "ping frame length must be 8")
		}
		if f.flags&h2FlagAck == 0 {
			return true, c.writeFrame(h2FramePING, h2FlagAck, 0, f.payload)
		}
		return true, nil
	case h2FrameGOAWAY:
		return false, io.EOF
	case h2FrameWindowUpdate:
		if len(f.payload) != 4 {
			return true, c.goawayConn(h2ErrorCodeProtocol, "window update length must be 4")
		}
		delta := int64(uint32(f.payload[0]&0x7f)<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3]))
		if delta == 0 {
			return true, c.goawayConn(h2ErrorCodeProtocol, "window update with zero increment")
		}
		if err := c.checkWindowOverflow(f.streamID, delta); err != nil {
			return true, err
		}
		c.flow.grant(f.streamID, delta)
		return true, nil
	case h2FramePRIORITY:
		return true, nil // ignored
	}
	return false, nil
}

// checkWindowOverflow rejects a WINDOW_UPDATE that would push the send
// window past 2^31-1 (RFC 9113 §6.9.1: MUST treat as FLOW_CONTROL_ERROR).
func (c *h2Conn) checkWindowOverflow(streamID uint32, delta int64) error {
	c.flow.mu.Lock()
	defer c.flow.mu.Unlock()
	var cur int64
	if streamID == 0 {
		cur = c.flow.conn
	} else {
		cur = c.flow.streams[streamID]
	}
	if cur+delta > 1<<31-1 {
		return c.goawayConn(h2ErrorCodeFlowControl, "window update overflows window")
	}
	return nil
}

// applyPeerSettings honors the settings that change our send accounting.
// SETTINGS_INITIAL_WINDOW_SIZE carries a connection error response because
// RFC 9113 §6.9.2 makes a negative resulting window FLOW_CONTROL_ERROR.
func (c *h2Conn) applyPeerSettings(payload []byte) error {
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		value := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		if id == 0x4 { // SETTINGS_INITIAL_WINDOW_SIZE: adjusts stream windows
			if err := c.flow.applyInitialWindow(value); err != nil {
				return err
			}
		}
	}
	return nil
}

// beginHeaderBlock starts (or rejects) accumulation of a header block on
// the stream. It returns false when the frame is a protocol violation that
// must end the connection.
func (c *h2Conn) beginHeaderBlock(f h2Frame, payload []byte) bool {
	if c.hdrOpen {
		// HEADERS while another block is open: RFC 9113 forbids
		// interleaving; a mid-block HEADERS corrupts the HPACK state.
		return false
	}
	if len(c.hdrBuf)+len(payload) > h2MaxHeaderListBytes {
		return false
	}
	c.hdrBuf = append(c.hdrBuf[:0], payload...)
	c.hdrStream = f.streamID
	c.hdrOpen = true
	c.hdrEndStream = f.flags&h2FlagEndStream != 0
	return true
}

// continueHeaderBlock appends a CONTINUATION payload. It returns false on
// the same protocol violations (not open, wrong stream, over cap).
func (c *h2Conn) continueHeaderBlock(f h2Frame) bool {
	if !c.hdrOpen || f.streamID != c.hdrStream {
		return false
	}
	if len(c.hdrBuf)+len(f.payload) > h2MaxHeaderListBytes {
		return false
	}
	c.hdrBuf = append(c.hdrBuf, f.payload...)
	return true
}

func (c *h2Conn) goawayConn(code uint32, why string) error {
	msg := append([]byte(why), 0)
	payload := make([]byte, 0, 8+len(msg))
	payload = append(payload, 0, 0, 0, 0) // last stream ID 0
	payload = append(payload, byte(code>>24), byte(code>>16), byte(code>>8), byte(code))
	payload = append(payload, msg...)
	if werr := c.writeFrame(h2FrameGOAWAY, 0, 0, payload); werr != nil {
		return werr
	}
	return fmt.Errorf("http2: %s", why)
}

// ---- server leg ----

type h2Server struct {
	h2Conn
	requests chan *http.Request
	current  uint32 // stream being answered by the serve loop

	// per-stream receive state, written by the read goroutine
	streamsMu  sync.Mutex
	streams    map[uint32]*h2InboundStream
	active     int   // streams with headers received, concurrency guard
	bodyBudget int64 // total buffered body bytes across the connection

	// streamEnded marks the current response stream as closed (END_STREAM
	// already sent), so FinishBody after a bodyless SubmitResponse is a
	// no-op instead of framing DATA after END_STREAM. Serve-loop goroutine
	// only.
	streamEnded bool
}

type h2InboundStream struct {
	req      *http.Request // set when HEADERS arrived without END_STREAM
	body     bytes.Buffer
	ended    bool
	overflow bool
}

func newH2Server(conn net.Conn, br *bufio.Reader) *h2Server {
	s := &h2Server{
		h2Conn: h2Conn{
			conn: conn,
			br:   br,
			flow: newH2Flow(),
		},
		requests: make(chan *http.Request, h2MaxConcurrentStreams*8),
		streams:  make(map[uint32]*h2InboundStream),
	}
	s.dec = hpack.NewDecoder(4096, s.onHeaderField)
	s.enc = hpack.NewEncoder(&s.encBuf)
	// Server speaks first: SETTINGS (initial stream window, concurrency
	// limit) plus a large connection receive window, then the per-stream
	// window rides on SETTINGS_INITIAL_WINDOW_SIZE.
	streamWindow := uint32(h2StreamRecvWindow)
	connWindow := uint32(h2ConnRecvWindow)
	settings := make([]byte, 0, 18)
	settings = append(settings, 0x00, 0x03) // SETTINGS_MAX_CONCURRENT_STREAMS
	settings = append(settings, 0, 0, byte(h2MaxConcurrentStreams>>8), byte(h2MaxConcurrentStreams))
	settings = append(settings, 0x00, 0x04) // INITIAL_WINDOW_SIZE
	settings = append(settings, byte(streamWindow>>24), byte(streamWindow>>16), byte(streamWindow>>8), byte(streamWindow))
	_ = s.writeFrame(h2FrameSETTINGS, 0, 0, settings)
	var wu [4]byte
	wu[0], wu[1], wu[2], wu[3] = byte(connWindow>>24)&0x7f, byte(connWindow>>16), byte(connWindow>>8), byte(connWindow)
	_ = s.writeFrame(h2FrameWindowUpdate, 0, 0, wu[:])
	go s.readLoop()
	return s
}

func (s *h2Server) NextRequest() (*http.Request, error) {
	select {
	case req := <-s.requests:
		s.current = h2StreamID(req)
		return req, nil
	case <-time.After(h2HeaderTimeout):
		return nil, fmt.Errorf("http2: timed out waiting for a request")
	}
}

// h2StreamID carries the h2 stream id on the request for response routing.
func h2StreamID(req *http.Request) uint32 {
	if v, ok := req.Context().Value(h2StreamKey{}).(uint32); ok {
		return v
	}
	return 0
}

type h2StreamKey struct{}

func (s *h2Server) readLoop() {
	preface := make([]byte, len(h2ClientPreface))
	if _, err := io.ReadFull(s.br, preface); err != nil {
		_ = s.conn.Close()
		return
	}
	if string(preface) != h2ClientPreface {
		_ = s.conn.Close()
		return
	}
	for {
		f, err := readH2Frame(s.br)
		if err != nil {
			_ = s.conn.Close()
			return
		}
		if handled, herr := s.handleCommonFrame(f); herr != nil || handled {
			if herr != nil {
				_ = s.conn.Close()
				return
			}
			continue
		}
		switch f.typ {
		case h2FrameHEADERS:
			if s.hdrOpen {
				// HEADERS mid-block: interleaving is a protocol error.
				_ = s.goawayConn(h2ErrorCodeProtocol, "headers while continuation open")
				_ = s.conn.Close()
				return
			}
			s.handleHeaders(f)
		case h2FrameContinuation:
			if !s.continueHeaderBlock(f) {
				_ = s.goawayConn(h2ErrorCodeProtocol, "invalid continuation frame")
				_ = s.conn.Close()
				return
			}
			if f.flags&h2FlagEndHeaders != 0 {
				s.hdrOpen = false
				s.finishHeaders(f.streamID, s.hdrEndStream)
			}
		case h2FrameDATA:
			if f.streamID == 0 || f.streamID%2 == 0 {
				// DATA never travels on stream 0, and even-numbered stream
				// IDs are server-initiated (RFC 9113 §5.1.1).
				_ = s.goawayConn(h2ErrorCodeProtocol, "data on invalid stream id")
				_ = s.conn.Close()
				return
			}
			s.streamsMu.Lock()
			_, known := s.streams[f.streamID]
			s.streamsMu.Unlock()
			if !known {
				// DATA on a stream we never opened is a connection error
				// (RFC 9113 §5.1).
				_ = s.goawayConn(h2ErrorCodeProtocol, "data on unknown stream")
				_ = s.conn.Close()
				return
			}
			s.handleData(f)
		case h2FrameRSTStream:
			s.flow.exclude(f.streamID)
			s.releaseStream(f.streamID)
		case h2FramePushPromise:
			_ = s.writeFrame(h2FrameRSTStream, 0, f.streamID, []byte{0, 0, 0, h2ErrorCodeProtocol})
		}
	}
}

func (s *h2Server) handleHeaders(f h2Frame) {
	payload := f.payload
	if f.flags&h2FlagPadded != 0 {
		if len(payload) < 1 || int(payload[0]) >= len(payload) {
			// Pad length beyond payload is a protocol error (RFC 9113 §6.2).
			_ = s.goawayConn(h2ErrorCodeProtocol, "invalid padding on headers")
			_ = s.conn.Close()
			return
		}
		pad := int(payload[0])
		payload = payload[1:]
		payload = payload[:len(payload)-pad]
	}
	if f.flags&h2FlagPriority != 0 {
		if len(payload) < 5 {
			_ = s.goawayConn(h2ErrorCodeProtocol, "truncated priority on headers")
			_ = s.conn.Close()
			return
		}
		payload = payload[5:]
	}
	if !s.beginHeaderBlock(f, payload) {
		_ = s.goawayConn(h2ErrorCodeProtocol, "invalid headers frame")
		_ = s.conn.Close()
		return
	}
	if f.flags&h2FlagEndHeaders != 0 {
		s.hdrOpen = false
		s.finishHeaders(f.streamID, f.flags&h2FlagEndStream != 0)
	}
}

func (s *h2Server) finishHeaders(streamID uint32, endStream bool) {
	fields, err := s.decodeHeaderBlock(s.hdrBuf, streamID)
	if err != nil {
		_ = s.writeFrame(h2FrameRSTStream, 0, streamID, []byte{0, 0, 0, h2ErrorCodeInternal})
		return
	}
	var method, path, scheme, authority string
	header := make(http.Header)
	for _, hf := range fields {
		switch hf.Name {
		case ":method":
			method = hf.Value
		case ":path":
			path = hf.Value
		case ":scheme":
			scheme = hf.Value
		case ":authority":
			authority = hf.Value
		default:
			if strings.HasPrefix(hf.Name, ":") {
				continue
			}
			header.Add(textproto.CanonicalMIMEHeaderKey(hf.Name), hf.Value)
		}
	}
	if method == "" || path == "" {
		_ = s.writeFrame(h2FrameRSTStream, 0, streamID, []byte{0, 0, 0, h2ErrorCodeInternal})
		return
	}
	u := &url.URL{Scheme: schemeOr(scheme, "https"), Host: authority, Path: path}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path = path[:i]
		u.RawQuery = path[i+1:]
	}

	ctx := context.WithValue(context.Background(), h2StreamKey{}, streamID)
	req := &http.Request{
		Method: method,
		URL:    u,
		Proto:  "HTTP/2.0",
		Header: header,
		Host:   authority,
		Body:   io.NopCloser(bytes.NewReader(nil)),
	}
	req = req.WithContext(ctx)
	s.streamsMu.Lock()
	if s.active >= h2MaxConcurrentStreams {
		s.streamsMu.Unlock()
		// At the advertised SETTINGS_MAX_CONCURRENT_STREAMS: refuse the
		// stream rather than queueing unbounded state.
		_ = s.writeFrame(h2FrameRSTStream, 0, streamID, []byte{0, 0, 0, h2ErrorCodeRefused})
		return
	}
	s.active++
	s.streamsMu.Unlock()
	if endStream {
		s.deliverRequest(req)
		return
	}
	// Body still in flight: keep the assembled request on the stream until
	// DATA completes it in finalizeData.
	s.streamsMu.Lock()
	s.streams[streamID] = &h2InboundStream{req: req}
	s.streamsMu.Unlock()
	// Track the stream's send window from creation: a peer SETTINGS
	// INITIAL_WINDOW_SIZE delta must apply to it (W1), and response DATA
	// takes from the tracked window rather than a stale default.
	s.flow.registerStream(streamID)
}

func (s *h2Server) handleData(f h2Frame) {
	payload := f.payload
	if f.flags&h2FlagPadded != 0 {
		if len(payload) < 1 || int(payload[0]) >= len(payload) {
			// Pad length beyond payload is a protocol error (RFC 9113 §6.2).
			_ = s.goawayConn(h2ErrorCodeProtocol, "invalid padding on data")
			_ = s.conn.Close()
			return
		}
		pad := int(payload[0])
		payload = payload[1:]
		payload = payload[:len(payload)-pad]
	}
	s.streamsMu.Lock()
	stream, ok := s.streams[f.streamID]
	refused := false
	if ok && !stream.ended {
		switch {
		case stream.overflow:
			// Already over the per-stream limit: discard and return window.
			s.grantRecvLocked(f.streamID, int64(len(payload)))
		case stream.body.Len()+len(payload) <= h2StreamBodyLimit && s.bodyBudget+int64(len(payload)) <= h2ConnBodyBudget:
			stream.body.Write(payload)
			s.bodyBudget += int64(len(payload))
			// Bytes stay buffered: the window is re-granted when the stream
			// is consumed or torn down, so buffered bodies apply
			// connection-wide backpressure instead of the old byte-for-byte
			// re-grant that let thousands of streams pile up 1 MiB each.
		case stream.body.Len()+len(payload) > h2StreamBodyLimit:
			stream.overflow = true
			s.grantRecvLocked(f.streamID, int64(len(payload)))
		default:
			// Connection-wide body budget exhausted: refuse this stream.
			s.active--
			if n := stream.body.Len(); n > 0 {
				s.bodyBudget -= int64(n)
				s.grantRecvLocked(f.streamID, int64(n))
			}
			delete(s.streams, f.streamID)
			s.grantRecvLocked(f.streamID, int64(len(payload)))
			refused = true
		}
		if f.flags&h2FlagEndStream != 0 {
			stream.ended = true
		}
	}
	s.streamsMu.Unlock()
	if refused {
		_ = s.writeFrame(h2FrameRSTStream, 0, f.streamID, []byte{0, 0, 0, h2ErrorCodeRefused})
		return
	}
	if ok && f.flags&h2FlagEndStream != 0 {
		s.finalizeData(f.streamID)
	}
}

// grantRecvLocked returns window for bytes we did not buffer. Callers must
// hold s.streamsMu.
func (s *h2Server) grantRecvLocked(streamID uint32, n int64) {
	if n <= 0 {
		return
	}
	var wu [4]byte
	wu[0], wu[1], wu[2], wu[3] = byte(n>>24)&0x7f, byte(n>>16), byte(n>>8), byte(n)
	_ = s.writeFrame(h2FrameWindowUpdate, 0, 0, wu[:])
	_ = s.writeFrame(h2FrameWindowUpdate, 0, streamID, wu[:])
}

// releaseStream returns a buffered stream's bytes to the connection budget
// and re-grants the window it consumed.
func (s *h2Server) releaseStream(streamID uint32) {
	s.streamsMu.Lock()
	stream, ok := s.streams[streamID]
	if ok {
		if n := stream.body.Len(); n > 0 {
			s.bodyBudget -= int64(n)
			s.grantRecvLocked(streamID, int64(n))
		}
		s.active--
		delete(s.streams, streamID)
	}
	s.streamsMu.Unlock()
}

func (s *h2Server) finalizeData(streamID uint32) {
	s.streamsMu.Lock()
	stream := s.streams[streamID]
	delete(s.streams, streamID)
	if stream != nil {
		// The serve loop now owns the buffered body: return the window it
		// consumed so the peer can keep uploading on other streams.
		if n := stream.body.Len(); n > 0 {
			s.bodyBudget -= int64(n)
			s.grantRecvLocked(streamID, int64(n))
		}
	}
	s.streamsMu.Unlock()
	if stream == nil {
		return
	}
	s.active--
	if stream.overflow {
		// Body too large to buffer: answer 413 on this stream alone and
		// keep the connection serving other streams.
		s.respondSimple(streamID, http.StatusRequestEntityTooLarge)
		return
	}
	if stream.req == nil {
		return
	}
	body := stream.body.Bytes()
	stream.req.Body = io.NopCloser(bytes.NewReader(body))
	stream.req.ContentLength = int64(len(body))
	s.deliverRequest(stream.req)
}

func (s *h2Server) respondSimple(streamID uint32, status int) {
	s.writeHeaderBlock(streamID, true, func(enc *hpack.Encoder) error {
		return enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	})
}

// SubmitResponse sends response HEADERS for the current request stream.
// A bodyless response is terminal: HEADERS carries END_STREAM so
// spec-strict clients see a complete stream (W4).
func (s *h2Server) SubmitResponse(resp *http.Response) error {
	streamID := s.current
	s.streamEnded = false
	clen := int64(-1)
	if v := resp.Header.Get("Content-Length"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			clen = n
		}
	}
	if resp.Body == nil || resp.Body == http.NoBody || clen == 0 {
		s.streamEnded = true
		return s.writeHeaderBlock(streamID, true, func(enc *hpack.Encoder) error {
			if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(resp.StatusCode)}); err != nil {
				return err
			}
			for name, vals := range resp.Header {
				if strings.EqualFold(name, "Connection") || strings.EqualFold(name, "Transfer-Encoding") {
					continue
				}
				if strings.EqualFold(name, "Content-Length") {
					// END_STREAM alone closes the stream; a Content-Length
					// header on a bodyless response invites a length check
					// against no DATA at all, so it is not re-emitted.
					continue
				}
				for _, v := range vals {
					if err := enc.WriteField(hpack.HeaderField{Name: strings.ToLower(name), Value: v}); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	return s.writeHeaderBlock(streamID, false, func(enc *hpack.Encoder) error {
		if err := enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(resp.StatusCode)}); err != nil {
			return err
		}
		for name, vals := range resp.Header {
			if strings.EqualFold(name, "Connection") || strings.EqualFold(name, "Transfer-Encoding") {
				continue
			}
			for _, v := range vals {
				if err := enc.WriteField(hpack.HeaderField{Name: strings.ToLower(name), Value: v}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// FinishBody streams the response body as DATA frames and closes the stream.
// It is a no-op when SubmitResponse already closed the stream (bodyless or
// zero-length responses).
func (s *h2Server) FinishBody(resp *http.Response) bool {
	streamID := s.current
	if s.streamEnded {
		return true // stream already complete with END_STREAM
	}
	buf := make([]byte, 16*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if werr := s.writeDATA(streamID, buf[:n], false); werr != nil {
				return false
			}
		}
		if err != nil {
			if werr := s.writeFrame(h2FrameDATA, h2FlagEndStream, streamID, nil); werr != nil {
				return false
			}
			return true
		}
	}
}

func (s *h2Server) Close() {
	_ = s.conn.Close()
}

// deliverRequest queues a request for the serve loop without ever blocking
// the read goroutine (a blocked readLoop cannot answer PINGs or process
// flow-control frames for the streams already queued). If the queue is
// full the connection is beyond saving, so it is failed loudly.
func (s *h2Server) deliverRequest(req *http.Request) {
	select {
	case s.requests <- req:
	default:
		_ = s.goawayConn(h2ErrorCodeInternal, "request queue overflow")
		_ = s.conn.Close()
	}
}

func schemeOr(scheme, fallback string) string {
	if scheme == "" {
		return fallback
	}
	return scheme
}

// ---- client leg (upstream) ----

type h2ClientConn struct {
	h2Conn
	streamID uint32

	respOnce   sync.Once
	respReady  chan struct{}
	respErr    error
	respStatus int
	respHeader http.Header
	respBodyR  *io.PipeReader
	respBodyW  *io.PipeWriter

	streamDone chan struct{}
	closeOnce  sync.Once
	done       chan struct{} // closed when the connection is dead (GOAWAY, IO error)
}

func newH2ClientConn(conn net.Conn) (*h2ClientConn, error) {
	c := &h2ClientConn{
		h2Conn: h2Conn{
			conn: conn,
			br:   bufio.NewReader(conn),
			flow: newH2Flow(),
		},
		streamDone: make(chan struct{}),
		done:       make(chan struct{}),
	}
	c.dec = hpack.NewDecoder(4096, c.onHeaderField)
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.streamID = 1
	// Client preface: magic + SETTINGS + a connection window bump.
	if _, err := conn.Write([]byte(h2ClientPreface)); err != nil {
		return nil, err
	}
	if err := c.writeFrame(h2FrameSETTINGS, 0, 0, nil); err != nil {
		return nil, err
	}
	var wu [4]byte
	wu[0], wu[1], wu[2], wu[3] = 0x40, 0, 0, 0 // 2^30
	if err := c.writeFrame(h2FrameWindowUpdate, 0, 0, wu[:]); err != nil {
		return nil, err
	}
	go c.readLoop()
	return c, nil
}

func (c *h2ClientConn) readLoop() {
	for {
		f, err := readH2Frame(c.br)
		if err != nil {
			c.abort(err)
			return
		}
		handled, herr := c.handleCommonFrame(f)
		if herr != nil {
			c.abort(herr)
			return
		}
		if handled {
			continue
		}
		switch f.typ {
		case h2FrameHEADERS:
			if c.hdrOpen {
				_ = c.goawayConn(h2ErrorCodeProtocol, "headers while continuation open")
				c.abort(fmt.Errorf("http2: headers while continuation open"))
				return
			}
			c.handleHeaders(f)
		case h2FrameContinuation:
			if !c.continueHeaderBlock(f) {
				_ = c.goawayConn(h2ErrorCodeProtocol, "invalid continuation frame")
				c.abort(fmt.Errorf("http2: invalid continuation frame"))
				return
			}
			if f.flags&h2FlagEndHeaders != 0 {
				c.hdrOpen = false
				c.finishHeaders()
			}
		case h2FrameDATA:
			c.handleData(f)
		case h2FrameRSTStream:
			// Per-stream error only: fail the in-flight round trip with the
			// code; the connection itself stays usable unless the peer also
			// sends GOAWAY (W5).
			code := uint32(f.payload[0])<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3])
			if len(f.payload) == 4 {
				c.failStream(fmt.Errorf("http2: stream reset by upstream, error code %d", code))
			} else {
				c.failStream(fmt.Errorf("http2: stream reset by upstream"))
			}
			c.flow.exclude(f.streamID)
		}
	}
}

// failStream surfaces a stream-scoped error to the pending RoundTrip without
// tearing down the whole connection.
func (c *h2ClientConn) failStream(err error) {
	c.respOnce.Do(func() {
		c.respErr = err
		close(c.respReady)
	})
	if c.respBodyW != nil {
		_ = c.respBodyW.CloseWithError(err)
	}
}

func (c *h2ClientConn) handleHeaders(f h2Frame) {
	payload := f.payload
	if f.flags&h2FlagPadded != 0 {
		if len(payload) < 1 {
			return
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return
		}
		payload = payload[:len(payload)-pad]
	}
	if f.flags&h2FlagPriority != 0 {
		if len(payload) < 5 {
			_ = c.goawayConn(h2ErrorCodeProtocol, "truncated priority on headers")
			c.abort(fmt.Errorf("http2: truncated priority on headers"))
			return
		}
		payload = payload[5:]
	}
	if !c.beginHeaderBlock(f, payload) {
		_ = c.goawayConn(h2ErrorCodeProtocol, "invalid headers frame")
		c.abort(fmt.Errorf("http2: invalid headers frame"))
		return
	}
	if f.flags&h2FlagEndHeaders != 0 {
		c.hdrOpen = false
		c.finishHeaders()
	}
}

func (c *h2ClientConn) finishHeaders() {
	fields, err := c.decodeHeaderBlock(c.hdrBuf, c.streamID)
	if err != nil {
		c.abort(err)
		return
	}
	header := make(http.Header)
	status := 0
	for _, hf := range fields {
		if hf.Name == ":status" {
			status, _ = strconv.Atoi(hf.Value)
			continue
		}
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		header.Add(textproto.CanonicalMIMEHeaderKey(hf.Name), hf.Value)
	}
	c.respStatus = status
	c.respHeader = header
	c.respOnce.Do(func() { close(c.respReady) })
}

func (c *h2ClientConn) handleData(f h2Frame) {
	// One in-flight stream at a time: the id currently being served is the
	// one RoundTrip just registered (c.streamID was bumped past it). DATA
	// on any other stream is a connection error (RFC 9113 §5.1).
	if current := c.streamID - 2; f.streamID != current {
		_ = c.goawayConn(h2ErrorCodeProtocol, "data on unknown stream")
		c.abort(fmt.Errorf("http2: data on unknown stream"))
		return
	}
	payload := f.payload
	if f.flags&h2FlagPadded != 0 {
		if len(payload) < 1 {
			return
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return
		}
		payload = payload[:len(payload)-pad]
	}
	if len(payload) > 0 && c.respBodyW != nil {
		if _, err := c.respBodyW.Write(payload); err != nil {
			// Reader side went away; keep draining so the connection stays
			// protocol-correct, but do not buffer.
		}
	}
	if len(payload) > 0 {
		var wu [4]byte
		wu[0], wu[1], wu[2], wu[3] = byte(len(payload)>>24)&0x7f, byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
		_ = c.writeFrame(h2FrameWindowUpdate, 0, 0, wu[:])
		_ = c.writeFrame(h2FrameWindowUpdate, 0, c.streamID, wu[:])
	}
	if f.flags&h2FlagEndStream != 0 {
		if c.respBodyW != nil {
			_ = c.respBodyW.Close()
		}
		select {
		case <-c.streamDone:
		default:
			close(c.streamDone)
		}
	}
}

func (c *h2ClientConn) abort(err error) {
	c.closeOnce.Do(func() { close(c.done) })
	c.flow.Shutdown()
	c.respOnce.Do(func() {
		c.respErr = err
		if c.respReady != nil {
			close(c.respReady)
		}
	})
	if c.respBodyW != nil {
		_ = c.respBodyW.CloseWithError(err)
	}
	if c.streamDone != nil {
		select {
		case <-c.streamDone:
		default:
			close(c.streamDone)
		}
	}
	_ = c.conn.Close()
}

func (c *h2ClientConn) RoundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	c.respOnce = sync.Once{}
	c.respReady = make(chan struct{})
	// Clear per-round-trip state: a previous stream's error or status must
	// not leak into this request (W5 keeps the connection alive, so the
	// struct is reused).
	c.respErr = nil
	c.respStatus = 0
	c.respHeader = nil
	c.respBodyR, c.respBodyW = io.Pipe()
	c.streamDone = make(chan struct{})
	streamID := c.streamID
	c.flow.registerStream(streamID) // open the stream at the current window
	c.streamID += 2

	endStream := req.Body == nil || req.Body == http.NoBody
	scheme := "https"
	if req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	}
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	path := req.URL.RequestURI()
	err := c.writeHeaderBlock(streamID, endStream, func(enc *hpack.Encoder) error {
		if e := enc.WriteField(hpack.HeaderField{Name: ":method", Value: req.Method}); e != nil {
			return e
		}
		if e := enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: scheme}); e != nil {
			return e
		}
		if e := enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority}); e != nil {
			return e
		}
		if e := enc.WriteField(hpack.HeaderField{Name: ":path", Value: path}); e != nil {
			return e
		}
		for name, vals := range req.Header {
			lname := strings.ToLower(name)
			switch lname {
			case "connection", "keep-alive", "transfer-encoding", "upgrade", "host":
				continue
			}
			for _, v := range vals {
				if e := enc.WriteField(hpack.HeaderField{Name: lname, Value: v}); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !endStream {
		buf := make([]byte, 16*1024)
		for {
			n, rerr := req.Body.Read(buf)
			if n > 0 {
				if werr := c.writeDATA(streamID, buf[:n], false); werr != nil {
					return nil, werr
				}
			}
			if rerr != nil {
				if werr := c.writeFrame(h2FrameDATA, h2FlagEndStream, streamID, nil); werr != nil {
					return nil, werr
				}
				break
			}
		}
	}

	select {
	case <-c.respReady:
	case <-c.done:
		if c.respErr != nil {
			return nil, c.respErr
		}
		return nil, fmt.Errorf("http2: connection closed by upstream")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(h2HeaderTimeout):
		return nil, fmt.Errorf("http2: upstream response headers timed out")
	}
	if c.respErr != nil {
		return nil, c.respErr
	}
	if c.respStatus == 0 {
		return nil, fmt.Errorf("http2: upstream sent no :status")
	}
	resp := &http.Response{
		StatusCode: c.respStatus,
		Status:     strconv.Itoa(c.respStatus) + " " + http.StatusText(c.respStatus),
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     c.respHeader,
		Body:       c.respBodyR,
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, perr := strconv.ParseInt(cl, 10, 64); perr == nil {
			resp.ContentLength = n
		}
	}
	return resp, nil
}

// FinishBody waits until the upstream stream is fully consumed.
func (c *h2ClientConn) FinishBody(resp *http.Response) bool {
	_ = resp.Body.Close()
	select {
	case <-c.streamDone:
		return true
	case <-time.After(idleTimeout):
		return false
	}
}

func (c *h2ClientConn) Close() {
	_ = c.conn.Close()
}
