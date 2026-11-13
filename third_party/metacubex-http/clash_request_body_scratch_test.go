package http

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestTheStreamingBodyScratchCap(t *testing.T) {
	previous := SetHTTP2StreamingBodyScratchMax(16 << 10)
	defer SetHTTP2StreamingBodyScratchMax(previous)
	if got := HTTP2RequestBodyScratchMax(-1); got != 16<<10 {
		t.Fatalf("a streaming body's ceiling %d, want 16 KiB", got)
	}
	if got := HTTP2RequestBodyScratchMax(1 << 20); got != 512<<10 {
		t.Fatalf("a body of known length capped at %d, want upstream's 512 KiB", got)
	}
	if got := SetHTTP2StreamingBodyScratchMax(4 << 20); got != 16<<10 {
		t.Fatalf("the setter handed back %d, want the 16 KiB it replaced", got)
	}
	if got := HTTP2RequestBodyScratchMax(-1); got != 512<<10 {
		t.Fatalf("a cap above upstream's ceiling reads %d, want it clamped to 512 KiB", got)
	}
	SetHTTP2StreamingBodyScratchMax(0)
	if got := HTTP2RequestBodyScratchMax(-1); got != 512<<10 {
		t.Fatalf("with no cap a streaming body's ceiling is %d, want upstream's 512 KiB", got)
	}
}

func TestTheOnDemandScratchIsForAStreamingPipeWithTheSwitchOn(t *testing.T) {
	previous := SetHTTP2StreamingBodyScratchOnDemand(false)
	defer SetHTTP2StreamingBodyScratchOnDemand(previous)
	pool := &sync.Pool{}
	pipe, _ := io.Pipe()
	if newHTTP2OnDemandScratch(pipe, false, 64<<10, pool) != nil {
		t.Fatal("an on-demand reader with the switch off")
	}
	if SetHTTP2StreamingBodyScratchOnDemand(true) {
		t.Fatal("the setter handed back true for a switch that was off")
	}
	if !HTTP2StreamingBodyScratchOnDemand() || newHTTP2OnDemandScratch(pipe, false, 64<<10, pool) == nil {
		t.Fatal("no on-demand reader for a streaming pipe with the switch on")
	}
	if newHTTP2OnDemandScratch(&readTrackingBody{ReadCloser: pipe}, false, 64<<10, pool) == nil {
		t.Fatal("no on-demand reader for a pipe under the Transport's read-tracking wrapper")
	}
	if newHTTP2OnDemandScratch(pipe, true, 64<<10, pool) != nil {
		t.Fatal("an on-demand reader for a body of known length")
	}
	for name, body := range map[string]io.Reader{
		"a reader of bytes":            bytes.NewReader([]byte("body")),
		"a pipe under another wrapper": io.NopCloser(pipe),
		"no body":                      nil,
	} {
		if newHTTP2OnDemandScratch(body, false, 64<<10, pool) != nil {
			t.Fatalf("an on-demand reader for %s", name)
		}
	}
	if newHTTP2OnDemandScratch(pipe, false, 0, pool) != nil {
		t.Fatal("an on-demand reader with no buffer to take")
	}
}

func TestTheOnDemandScratchHoldsNothingWhileTheBodyIsSilent(t *testing.T) {
	previous := SetHTTP2StreamingBodyScratchOnDemand(true)
	defer SetHTTP2StreamingBodyScratchOnDemand(previous)
	pool := &sync.Pool{}
	reader, writer := io.Pipe()
	scratch := newHTTP2OnDemandScratch(reader, false, 64, pool)
	type read struct {
		data string
		err  error
	}
	reads := make(chan read)
	next := func() {
		go func() {
			buf, n, err := scratch.Read(reader)
			reads <- read{string(buf[:n]), err}
		}()
	}
	arrives := func(want string) {
		t.Helper()
		select {
		case got := <-reads:
			if got.data != want || got.err != nil {
				t.Fatalf("read %q, %v; want the whole write %q", got.data, got.err, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("the write %q was not read with no write behind it", want)
		}
	}
	next()
	select {
	case got := <-reads:
		t.Fatalf("a read of a silent body returned %q, %v", got.data, got.err)
	case <-time.After(50 * time.Millisecond):
	}
	if scratch.held != nil {
		t.Fatal("a buffer is held while the body is silent")
	}
	if _, err := writer.Write([]byte("hello, tunnel")); err != nil {
		t.Fatal(err)
	}
	arrives("hello, tunnel")
	held := scratch.held
	if held == nil || len(*held) != 64 {
		t.Fatalf("after a read the buffer held is %v, want the 64 bytes asked for", held)
	}
	scratch.Release()
	if scratch.held != nil {
		t.Fatal("a buffer is held after the release")
	}
	scratch.Release()
	next()
	if _, err := writer.Write([]byte("k")); err != nil {
		t.Fatal(err)
	}
	arrives("k")
	scratch.Release()
	_ = writer.Close()
	next()
	if got := <-reads; got.data != "" || got.err != io.EOF {
		t.Fatalf("at the body's end read %q, %v; want nothing and EOF", got.data, got.err)
	}
	if scratch.held != nil {
		t.Fatal("a buffer was taken for a read that brought nothing")
	}
}

func TestTheOnDemandScratchLosesNoByteOfTheBody(t *testing.T) {
	previous := SetHTTP2StreamingBodyScratchOnDemand(true)
	defer SetHTTP2StreamingBodyScratchOnDemand(previous)
	body := make([]byte, 1000)
	for i := range body {
		body[i] = byte(i * 7)
	}
	ones := make([]int, len(body))
	for i := range ones {
		ones[i] = 1
	}
	failed := errors.New("the body failed")
	for name, c := range map[string]struct {
		writes  []int
		end     error
		wantErr error
	}{
		"all in one write":          {[]int{1000}, nil, io.EOF},
		"a byte at a time":          {ones, nil, io.EOF},
		"writes about the buffer":   {[]int{1, 6, 7, 8, 0, 63, 64, 65, 0, 300, 486}, nil, io.EOF},
		"an empty write at the end": {[]int{1000, 0}, nil, io.EOF},
		"an error after some bytes": {[]int{300}, failed, failed},
		"an empty body":             {nil, nil, io.EOF},
	} {
		for _, size := range []int{1, 7, 64, 4096} {
			reader, writer := io.Pipe()
			want := 0
			for _, n := range c.writes {
				want += n
			}
			go func() {
				at := 0
				for _, n := range c.writes {
					if _, err := writer.Write(body[at : at+n]); err != nil {
						return
					}
					at += n
				}
				_ = writer.CloseWithError(c.end)
			}()
			scratch := newHTTP2OnDemandScratch(reader, false, size, &sync.Pool{})
			var got []byte
			var err error
			for reads := 0; err == nil; reads++ {
				if reads > 2*len(body)+len(c.writes)+2 {
					t.Fatalf("%s, buffer %d: the body does not end", name, size)
				}
				var buf []byte
				var n int
				buf, n, err = scratch.Read(reader)
				if n > size {
					t.Fatalf("%s, buffer %d: a read of %d bytes", name, size, n)
				}
				got = append(got, buf[:n]...)
				scratch.Release()
			}
			_ = reader.Close()
			if err != c.wantErr || !bytes.Equal(got, body[:want]) {
				t.Errorf("%s, buffer %d: %d bytes and %v, want %d and %v", name, size, len(got), err, want, c.wantErr)
			}
		}
	}
}
