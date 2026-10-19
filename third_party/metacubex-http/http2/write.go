// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"bytes"
	"fmt"
	"log"
	"net/url"

	"github.com/metacubex/http"
	"github.com/metacubex/http/internal/httpcommon"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

type writeFramer interface {
	writeFrame(writeContext) error

	staysWithinBuffer(size int) bool
}

type writeContext interface {
	Framer() *Framer
	Flush() error
	CloseConn() error
	HeaderEncoder() (*hpack.Encoder, *bytes.Buffer)
}

func writeEndsStream(w writeFramer) bool {
	switch v := w.(type) {
	case *writeData:
		return v.endStream
	case *writeResHeaders:
		return v.endStream
	case nil:
		panic("writeEndsStream called on nil writeFramer")
	}
	return false
}

type flushFrameWriter struct{}

func (flushFrameWriter) writeFrame(ctx writeContext) error {
	return ctx.Flush()
}

func (flushFrameWriter) staysWithinBuffer(max int) bool { return false }

type writeSettings []Setting

func (s writeSettings) staysWithinBuffer(max int) bool {
	const settingSize = 6
	return frameHeaderLen+settingSize*len(s) <= max

}

func (s writeSettings) writeFrame(ctx writeContext) error {
	return ctx.Framer().WriteSettings([]Setting(s)...)
}

type writeGoAway struct {
	maxStreamID uint32
	code        ErrCode
}

func (p *writeGoAway) writeFrame(ctx writeContext) error {
	err := ctx.Framer().WriteGoAway(p.maxStreamID, p.code, nil)
	ctx.Flush()
	return err
}

func (*writeGoAway) staysWithinBuffer(max int) bool { return false }

type writeData struct {
	streamID  uint32
	p         []byte
	endStream bool
}

func (w *writeData) String() string {
	return fmt.Sprintf("writeData(stream=%d, p=%d, endStream=%v)", w.streamID, len(w.p), w.endStream)
}

func (w *writeData) writeFrame(ctx writeContext) error {
	return ctx.Framer().WriteData(w.streamID, w.endStream, w.p)
}

func (w *writeData) staysWithinBuffer(max int) bool {
	return frameHeaderLen+len(w.p) <= max
}

type handlerPanicRST struct {
	StreamID uint32
}

func (hp handlerPanicRST) writeFrame(ctx writeContext) error {
	return ctx.Framer().WriteRSTStream(hp.StreamID, ErrCodeInternal)
}

func (hp handlerPanicRST) staysWithinBuffer(max int) bool { return frameHeaderLen+4 <= max }

func (se StreamError) writeFrame(ctx writeContext) error {
	return ctx.Framer().WriteRSTStream(se.StreamID, se.Code)
}

func (se StreamError) staysWithinBuffer(max int) bool { return frameHeaderLen+4 <= max }

type writePing struct {
	data [8]byte
}

func (w writePing) writeFrame(ctx writeContext) error {
	return ctx.Framer().WritePing(false, w.data)
}

func (w writePing) staysWithinBuffer(max int) bool { return frameHeaderLen+len(w.data) <= max }

type writePingAck struct{ pf *PingFrame }

func (w writePingAck) writeFrame(ctx writeContext) error {
	return ctx.Framer().WritePing(true, w.pf.Data)
}

func (w writePingAck) staysWithinBuffer(max int) bool { return frameHeaderLen+len(w.pf.Data) <= max }

type writeSettingsAck struct{}

func (writeSettingsAck) writeFrame(ctx writeContext) error {
	return ctx.Framer().WriteSettingsAck()
}

func (writeSettingsAck) staysWithinBuffer(max int) bool { return frameHeaderLen <= max }

func splitHeaderBlock(ctx writeContext, headerBlock []byte, fn func(ctx writeContext, frag []byte, firstFrag, lastFrag bool) error) error {
	const maxFrameSize = 16384

	first := true
	for len(headerBlock) > 0 {
		frag := headerBlock
		if len(frag) > maxFrameSize {
			frag = frag[:maxFrameSize]
		}
		headerBlock = headerBlock[len(frag):]
		if err := fn(ctx, frag, first, len(headerBlock) == 0); err != nil {
			return err
		}
		first = false
	}
	return nil
}

type writeResHeaders struct {
	streamID    uint32
	httpResCode int
	h           http.Header
	trailers    []string
	endStream   bool

	date          string
	contentType   string
	contentLength string
}

func encKV(enc *hpack.Encoder, k, v string) {
	if VerboseLogs {
		log.Printf("http2: server encoding header %q = %q", k, v)
	}
	enc.WriteField(hpack.HeaderField{Name: k, Value: v})
}

func (w *writeResHeaders) staysWithinBuffer(max int) bool {
	return false
}

func (w *writeResHeaders) writeFrame(ctx writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	if w.httpResCode != 0 {
		encKV(enc, ":status", httpCodeString(w.httpResCode))
	}

	encodeHeaders(enc, w.h, w.trailers)

	if w.contentType != "" {
		encKV(enc, "content-type", w.contentType)
	}
	if w.contentLength != "" {
		encKV(enc, "content-length", w.contentLength)
	}
	if w.date != "" {
		encKV(enc, "date", w.date)
	}

	headerBlock := buf.Bytes()
	if len(headerBlock) == 0 && w.trailers == nil {
		panic("unexpected empty hpack")
	}

	return splitHeaderBlock(ctx, headerBlock, w.writeHeaderBlock)
}

func (w *writeResHeaders) writeHeaderBlock(ctx writeContext, frag []byte, firstFrag, lastFrag bool) error {
	if firstFrag {
		return ctx.Framer().WriteHeaders(HeadersFrameParam{
			StreamID:      w.streamID,
			BlockFragment: frag,
			EndStream:     w.endStream,
			EndHeaders:    lastFrag,
		})
	} else {
		return ctx.Framer().WriteContinuation(w.streamID, lastFrag, frag)
	}
}

type writePushPromise struct {
	streamID uint32
	method   string
	url      *url.URL
	h        http.Header

	allocatePromisedID func() (uint32, error)
	promisedID         uint32
}

func (w *writePushPromise) staysWithinBuffer(max int) bool {
	return false
}

func (w *writePushPromise) writeFrame(ctx writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()

	encKV(enc, ":method", w.method)
	encKV(enc, ":scheme", w.url.Scheme)
	encKV(enc, ":authority", w.url.Host)
	encKV(enc, ":path", w.url.RequestURI())
	encodeHeaders(enc, w.h, nil)

	headerBlock := buf.Bytes()
	if len(headerBlock) == 0 {
		panic("unexpected empty hpack")
	}

	return splitHeaderBlock(ctx, headerBlock, w.writeHeaderBlock)
}

func (w *writePushPromise) writeHeaderBlock(ctx writeContext, frag []byte, firstFrag, lastFrag bool) error {
	if firstFrag {
		return ctx.Framer().WritePushPromise(PushPromiseParam{
			StreamID:      w.streamID,
			PromiseID:     w.promisedID,
			BlockFragment: frag,
			EndHeaders:    lastFrag,
		})
	} else {
		return ctx.Framer().WriteContinuation(w.streamID, lastFrag, frag)
	}
}

type write100ContinueHeadersFrame struct {
	streamID uint32
}

func (w write100ContinueHeadersFrame) writeFrame(ctx writeContext) error {
	enc, buf := ctx.HeaderEncoder()
	buf.Reset()
	encKV(enc, ":status", "100")
	return ctx.Framer().WriteHeaders(HeadersFrameParam{
		StreamID:      w.streamID,
		BlockFragment: buf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
}

func (w write100ContinueHeadersFrame) staysWithinBuffer(max int) bool {
	return 9+2*(len(":status")+len("100")) <= max
}

type writeWindowUpdate struct {
	streamID uint32
	n        uint32
}

func (wu writeWindowUpdate) staysWithinBuffer(max int) bool { return frameHeaderLen+4 <= max }

func (wu writeWindowUpdate) writeFrame(ctx writeContext) error {
	return ctx.Framer().WriteWindowUpdate(wu.streamID, wu.n)
}

func encodeHeaders(enc *hpack.Encoder, h http.Header, keys []string) {
	if keys == nil {
		sorter := sorterPool.Get().(*sorter)
		defer sorterPool.Put(sorter)
		keys = sorter.Keys(h)
	}
	for _, k := range keys {
		vv := h[k]
		k, ascii := httpcommon.LowerHeader(k)
		if !ascii {
			continue
		}
		if !validWireHeaderFieldName(k) {
			continue
		}
		isTE := k == "transfer-encoding"
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				continue
			}
			if isTE && v != "trailers" {
				continue
			}
			encKV(enc, k, v)
		}
	}
}
