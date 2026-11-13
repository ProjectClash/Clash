package http

import (
	"io"
	"sync"
	"sync/atomic"
)

var http2StreamingBodyScratchCap atomic.Int64

const http2UpstreamRequestBodyScratchMax = 512 << 10

func SetHTTP2StreamingBodyScratchMax(bytes int) (previous int) {
	if bytes > http2UpstreamRequestBodyScratchMax {
		bytes = http2UpstreamRequestBodyScratchMax
	}
	if bytes < 0 {
		bytes = 0
	}
	return int(http2StreamingBodyScratchCap.Swap(int64(bytes)))
}

func HTTP2RequestBodyScratchMax(contentLength int64) int64 {
	if n := http2StreamingBodyScratchCap.Load(); n > 0 && contentLength == -1 {
		return n
	}
	return http2UpstreamRequestBodyScratchMax
}

var http2StreamingBodyScratchOnDemand atomic.Bool

func SetHTTP2StreamingBodyScratchOnDemand(on bool) (previous bool) {
	return http2StreamingBodyScratchOnDemand.Swap(on)
}

func HTTP2StreamingBodyScratchOnDemand() bool { return http2StreamingBodyScratchOnDemand.Load() }

type http2OnDemandScratch struct {
	pool *sync.Pool
	size int
	held *[]byte
}

func newHTTP2OnDemandScratch(body io.Reader, hasContentLength bool, size int, pool *sync.Pool) *http2OnDemandScratch {
	if hasContentLength || size < 1 || !http2StreamingBodyScratchOnDemand.Load() || !http2BodyIsAPipe(body) {
		return nil
	}
	return &http2OnDemandScratch{pool: pool, size: size}
}

func http2BodyIsAPipe(body io.Reader) bool {
	if tracked, ok := body.(*readTrackingBody); ok {
		body = tracked.ReadCloser
	}
	_, ok := body.(*io.PipeReader)
	return ok
}

func (s *http2OnDemandScratch) Read(body io.Reader) (buf []byte, n int, err error) {
	if _, err = body.Read(nil); err != nil {
		return nil, 0, err
	}
	bp, ok := s.pool.Get().(*[]byte)
	if !ok || len(*bp) < s.size {
		fresh := make([]byte, s.size)
		bp = &fresh
	}
	s.held = bp
	buf = *bp
	n, err = body.Read(buf)
	return buf, n, err
}

func (s *http2OnDemandScratch) Release() {
	if s.held != nil {
		s.pool.Put(s.held)
		s.held = nil
	}
}
