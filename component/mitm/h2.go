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
//   - request bodies buffered up to h2StreamBodyLimit, larger bodies are
//     answered 413 rather than streamed, keeping memory bounded;
//   - connection-level flow control respected with wait-on-window for the
//     data we send, and WINDOW_UPDATEs issued for the data we receive.

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

	// We never emit a payload larger than the spec's default max frame size.
	h2MaxWriteFrame = 1 << 14
	// Request bodies buffer up to 1 MiB per stream; beyond that the stream is
	// refused with 413 instead of buffering without bound.
	h2StreamBodyLimit = 1 << 20
	// Connection-level receive window we advertise and grant.
	h2ConnRecvWindow = 1 << 30
	// Per-stream receive window we advertise.
	h2StreamRecvWindow = 1 << 20
	// Peer's initial send window per spec until their SETTINGS say otherwise.
	h2InitialSendWindow = 65535

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
type h2Flow struct {
	mu       sync.Mutex
	cond     *sync.Cond
	conn     int64
	streams  map[uint32]int64
	excluded map[uint32]bool // streams closed locally; stop waiting on them
}

func newH2Flow() *h2Flow {
	f := &h2Flow{conn: h2InitialSendWindow, streams: make(map[uint32]int64), excluded: make(map[uint32]bool)}
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
			streamAvail = h2InitialSendWindow
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

func (f *h2Flow) grant(streamID uint32, delta int64) {
	f.mu.Lock()
	if streamID == 0 {
		f.conn += delta
	} else {
		f.streams[streamID] += delta
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *h2Flow) exclude(streamID uint32) {
	f.mu.Lock()
	f.excluded[streamID] = true
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
	// then the block is decoded in one shot.
	hdrBuf      []byte
	hdrStream   uint32
	dec         *hpack.Decoder
	pendingHdrs *[]hpack.HeaderField

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
	chunkMax := h2MaxWriteFrame
	if len(data) < chunkMax {
		chunkMax = len(data)
	}
	for len(data) > 0 {
		n := c.flow.take(streamID, int64(chunkMax))
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
		if f.flags&h2FlagAck == 0 {
			c.applyPeerSettings(f.payload)
			return true, c.writeFrame(h2FrameSETTINGS, h2FlagAck, 0, nil)
		}
		return true, nil
	case h2FramePING:
		if f.flags&h2FlagAck == 0 {
			return true, c.writeFrame(h2FramePING, h2FlagAck, 0, f.payload)
		}
		return true, nil
	case h2FrameGOAWAY:
		return false, io.EOF
	case h2FrameWindowUpdate:
		if len(f.payload) == 4 {
			delta := int64(uint32(f.payload[0]&0x7f)<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3]))
			if delta > 0 {
				c.flow.grant(f.streamID, delta)
			}
		}
		return true, nil
	case h2FramePRIORITY:
		return true, nil // ignored
	}
	return false, nil
}

// applyPeerSettings honors the settings that change our send accounting.
func (c *h2Conn) applyPeerSettings(payload []byte) {
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		value := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		if id == 0x4 { // SETTINGS_INITIAL_WINDOW_SIZE: adjusts stream windows
			c.flow.mu.Lock()
			for sid, w := range c.flow.streams {
				c.flow.streams[sid] = w - h2InitialSendWindow + int64(value)
			}
			c.flow.cond.Broadcast()
			c.flow.mu.Unlock()
		}
	}
}

// ---- server leg ----

type h2Server struct {
	h2Conn
	requests chan *http.Request
	current  uint32 // stream being answered by the serve loop

	// per-stream receive state, written by the read goroutine
	streamsMu sync.Mutex
	streams   map[uint32]*h2InboundStream
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
		requests: make(chan *http.Request, 16),
		streams:  make(map[uint32]*h2InboundStream),
	}
	s.dec = hpack.NewDecoder(4096, s.onHeaderField)
	s.enc = hpack.NewEncoder(&s.encBuf)
	// Server speaks first: SETTINGS plus a large connection receive window,
	// then the per-stream window rides on SETTINGS_INITIAL_WINDOW_SIZE.
	streamWindow := uint32(h2StreamRecvWindow)
	connWindow := uint32(h2ConnRecvWindow)
	settings := make([]byte, 0, 12)
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
			s.handleHeaders(f)
		case h2FrameContinuation:
			s.hdrBuf = append(s.hdrBuf, f.payload...)
			if f.flags&h2FlagEndHeaders != 0 {
				s.finishHeaders(f.streamID, false)
			}
		case h2FrameDATA:
			s.handleData(f)
		case h2FrameRSTStream:
			s.flow.exclude(f.streamID)
			s.streamsMu.Lock()
			delete(s.streams, f.streamID)
			s.streamsMu.Unlock()
		case h2FramePushPromise:
			_ = s.writeFrame(h2FrameRSTStream, 0, f.streamID, []byte{0, 0, 0, h2ErrorCodeRefused})
		}
	}
}

func (s *h2Server) handleHeaders(f h2Frame) {
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
			return
		}
		payload = payload[5:]
	}
	s.hdrBuf = append(s.hdrBuf[:0], payload...)
	s.hdrStream = f.streamID
	if f.flags&h2FlagEndHeaders != 0 {
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
	if endStream {
		s.requests <- req
		return
	}
	// Body still in flight: keep the assembled request on the stream until
	// DATA completes it in finalizeData.
	s.streamsMu.Lock()
	s.streams[streamID] = &h2InboundStream{req: req}
	s.streamsMu.Unlock()
}

func (s *h2Server) handleData(f h2Frame) {
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
	// Grant the peer window for everything received, buffered or discarded,
	// so a large upload cannot stall the connection's other streams.
	var wu [4]byte
	grant := uint32(len(payload))
	if grant > 0 {
		wu[0], wu[1], wu[2], wu[3] = byte(grant>>24)&0x7f, byte(grant>>16), byte(grant>>8), byte(grant)
		_ = s.writeFrame(h2FrameWindowUpdate, 0, 0, wu[:])
		_ = s.writeFrame(h2FrameWindowUpdate, 0, f.streamID, wu[:])
	}
	s.streamsMu.Lock()
	stream, ok := s.streams[f.streamID]
	if ok && !stream.ended {
		if stream.body.Len()+len(payload) <= h2StreamBodyLimit {
			stream.body.Write(payload)
		} else {
			stream.overflow = true
		}
		if f.flags&h2FlagEndStream != 0 {
			stream.ended = true
		}
	}
	s.streamsMu.Unlock()
	if ok && f.flags&h2FlagEndStream != 0 {
		s.finalizeData(f.streamID)
	}
}

func (s *h2Server) finalizeData(streamID uint32) {
	s.streamsMu.Lock()
	stream := s.streams[streamID]
	delete(s.streams, streamID)
	s.streamsMu.Unlock()
	if stream == nil {
		return
	}
	if stream.overflow {
		// Body too large to buffer: answer 413 on this stream alone and keep
		// the connection serving other streams.
		s.respondSimple(streamID, http.StatusRequestEntityTooLarge)
		return
	}
	if stream.req == nil {
		return
	}
	body := stream.body.Bytes()
	stream.req.Body = io.NopCloser(bytes.NewReader(body))
	stream.req.ContentLength = int64(len(body))
	s.requests <- stream.req
}

func (s *h2Server) respondSimple(streamID uint32, status int) {
	s.writeHeaderBlock(streamID, true, func(enc *hpack.Encoder) error {
		return enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	})
}

// SubmitResponse sends response HEADERS for the current request stream.
func (s *h2Server) SubmitResponse(resp *http.Response) error {
	streamID := s.current
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
func (s *h2Server) FinishBody(resp *http.Response) bool {
	streamID := s.current
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
}

func newH2ClientConn(conn net.Conn) (*h2ClientConn, error) {
	c := &h2ClientConn{
		h2Conn: h2Conn{
			conn: conn,
			br:   bufio.NewReader(conn),
			flow: newH2Flow(),
		},
		streamDone: make(chan struct{}),
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
			c.handleHeaders(f)
		case h2FrameContinuation:
			c.hdrBuf = append(c.hdrBuf, f.payload...)
			if f.flags&h2FlagEndHeaders != 0 {
				c.finishHeaders()
			}
		case h2FrameDATA:
			c.handleData(f)
		case h2FrameRSTStream:
			c.abort(fmt.Errorf("http2: upstream reset stream"))
			return
		}
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
			return
		}
		payload = payload[5:]
	}
	c.hdrBuf = append(c.hdrBuf[:0], payload...)
	if f.flags&h2FlagEndHeaders != 0 {
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
	c.respOnce.Do(func() {
		c.respErr = err
		close(c.respReady)
	})
	if c.respBodyW != nil {
		_ = c.respBodyW.CloseWithError(err)
	}
	select {
	case <-c.streamDone:
	default:
		close(c.streamDone)
	}
	_ = c.conn.Close()
}

func (c *h2ClientConn) RoundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	c.respOnce = sync.Once{}
	c.respReady = make(chan struct{})
	c.respBodyR, c.respBodyW = io.Pipe()
	c.streamDone = make(chan struct{})
	streamID := c.streamID
	c.flow.grant(streamID, 0) // register the stream at initial window
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
