package net

import (
	"bytes"
	"errors"
	"io"
	stdnet "net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

func TestRelayCopyPreservesChunkReaderBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 1024, 2047, 2048, 2049, 4096, 16384, 32769} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i*31 ^ i>>7)
			}
			source := bufio.NewChunkReader(bytes.NewReader(payload), 16384)
			var output bytes.Buffer
			n, err := relayCopy(&output, source)
			if err != nil || n != int64(size) || !bytes.Equal(output.Bytes(), payload) {
				t.Fatalf("relayCopy: n=%d output=%d error=%v; want %d intact bytes", n, output.Len(), err, size)
			}
		})
	}
}

func TestRelayCopyPreservesCachedBytesAndCounters(t *testing.T) {
	const cached = "cached-"
	const streamed = "streamed"
	var readBytes, writtenBytes int64
	source := &relayReadCounter{
		Reader: &relayCachedReader{
			cached:   []byte(cached),
			upstream: strings.NewReader(streamed),
		},
		count: func(n int64) { readBytes += n },
	}
	var output bytes.Buffer
	destination := &relayWriteCounter{
		Writer: &output,
		count:  func(n int64) { writtenBytes += n },
	}

	n, err := relayCopy(destination, source)
	if err != nil {
		t.Fatalf("relayCopy() error = %v", err)
	}
	want := cached + streamed
	if got := output.String(); got != want {
		t.Fatalf("relayCopy() output = %q, want %q", got, want)
	}
	if n != int64(len(streamed)) {
		t.Errorf("relayCopy() bytes = %d, want streamed length %d", n, len(streamed))
	}
	if readBytes != int64(len(want)) {
		t.Errorf("read counter = %d, want %d", readBytes, len(want))
	}
	if writtenBytes != int64(len(want)) {
		t.Errorf("write counter = %d, want %d", writtenBytes, len(want))
	}
}

func TestRelayCopyPreservesReplaceableHandshakeReader(t *testing.T) {
	source := &relayReplaceableReader{
		handshake: []byte("handshake-"),
		upstream:  strings.NewReader("payload"),
	}
	var output bytes.Buffer

	_, err := relayCopy(&output, source)
	if err != nil {
		t.Fatalf("relayCopy() error = %v", err)
	}
	if got, want := output.String(), "handshake-payload"; got != want {
		t.Fatalf("relayCopy() output = %q, want %q", got, want)
	}
}

func TestRelayCopyReportsFirstWriteHandshakeFailure(t *testing.T) {
	writeErr := errors.New("write failed")
	source := &relayHandshakeReporter{Reader: strings.NewReader("payload")}

	_, err := relayCopy(relayErrorWriter{err: writeErr}, source)
	if !errors.Is(err, writeErr) {
		t.Fatalf("relayCopy() error = %v, want %v", err, writeErr)
	}
	if !source.called {
		t.Fatal("relayCopy() did not report the first write failure to the handshake source")
	}
}

func TestRelayPreservesTCPHalfClose(t *testing.T) {
	leftClient, leftRelay := newRelayTCPPair(t)
	rightClient, rightRelay := newRelayTCPPair(t)
	defer leftClient.Close()
	defer rightClient.Close()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []*stdnet.TCPConn{leftClient, leftRelay, rightClient, rightRelay} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline() error = %v", err)
		}
	}

	relayDone := make(chan struct{})
	go func() {
		Relay(leftRelay, rightRelay)
		close(relayDone)
	}()

	const request = "request"
	if _, err := leftClient.Write([]byte(request)); err != nil {
		t.Fatalf("left Write() error = %v", err)
	}
	if err := leftClient.CloseWrite(); err != nil {
		t.Fatalf("left CloseWrite() error = %v", err)
	}
	if got, err := io.ReadAll(rightClient); err != nil || string(got) != request {
		t.Fatalf("right ReadAll() = %q, %v; want %q, nil", got, err, request)
	}

	const response = "response"
	if _, err := rightClient.Write([]byte(response)); err != nil {
		t.Fatalf("right Write() error = %v", err)
	}
	if err := rightClient.CloseWrite(); err != nil {
		t.Fatalf("right CloseWrite() error = %v", err)
	}
	if got, err := io.ReadAll(leftClient); err != nil || string(got) != response {
		t.Fatalf("left ReadAll() = %q, %v; want %q, nil", got, err, response)
	}

	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay() did not return after both TCP half-closes")
	}
}

func TestRelayStopsWhenPeerCloses(t *testing.T) {
	left, leftRelay := stdnet.Pipe()
	right, rightRelay := stdnet.Pipe()
	defer right.Close()
	done := make(chan struct{})
	go func() { Relay(leftRelay, rightRelay); close(done) }()
	left.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Relay remained blocked after peer close")
	}
}

func BenchmarkRelayCopyStream(b *testing.B) {
	payload := bytes.Repeat([]byte("relay-data"), 6554)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, err := relayCopy(io.Discard, bytes.NewReader(payload))
		if err != nil || n != int64(len(payload)) {
			b.Fatalf("n=%d err=%v", n, err)
		}
	}
}

func BenchmarkRelayCopyChunkReader(b *testing.B) {
	payload := bytes.Repeat([]byte("chunk-data"), 6554)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, err := relayCopy(io.Discard, bufio.NewChunkReader(bytes.NewReader(payload), 16384))
		if err != nil || n != int64(len(payload)) {
			b.Fatalf("n=%d err=%v", n, err)
		}
	}
}

type relayCachedReader struct {
	cached   []byte
	upstream io.Reader
}

func (r *relayCachedReader) ReadCached() *buf.Buffer {
	if r.cached == nil {
		return nil
	}
	buffer := buf.As(r.cached)
	r.cached = nil
	return buffer
}

func (r *relayCachedReader) Read(p []byte) (int, error) {
	return r.upstream.Read(p)
}

type relayReadCounter struct {
	io.Reader
	count N.CountFunc
}

func (r *relayReadCounter) UnwrapReader() (io.Reader, []N.CountFunc) {
	return r.Reader, []N.CountFunc{r.count}
}

type relayWriteCounter struct {
	io.Writer
	count N.CountFunc
}

func (w *relayWriteCounter) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return w.Writer, []N.CountFunc{w.count}
}

type relayReplaceableReader struct {
	handshake       []byte
	upstream        io.Reader
	replaceable     bool
	maxReadCapacity int
}

func (r *relayReplaceableReader) Read(p []byte) (int, error) {
	if len(p) > r.maxReadCapacity {
		r.maxReadCapacity = len(p)
	}
	if !r.replaceable {
		n := copy(p, r.handshake)
		r.replaceable = true
		return n, nil
	}
	return r.upstream.Read(p)
}

func (r *relayReplaceableReader) ReaderReplaceable() bool {
	return r.replaceable
}

func (*relayReplaceableReader) ReaderPossiblyReplaceable() bool {
	return true
}

func (r *relayReplaceableReader) Upstream() any {
	return r.upstream
}

type relayHandshakeReporter struct {
	io.Reader
	called bool
}

func (r *relayHandshakeReporter) HandshakeFailure(error) error {
	r.called = true
	return nil
}

type relayErrorWriter struct {
	err error
}

func (w relayErrorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func newRelayTCPPair(t *testing.T) (*stdnet.TCPConn, *stdnet.TCPConn) {
	t.Helper()
	listener, err := stdnet.ListenTCP("tcp4", &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan *stdnet.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := stdnet.DialTCP("tcp4", nil, listener.Addr().(*stdnet.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	select {
	case server := <-accepted:
		return client, server
	case err := <-acceptErr:
		client.Close()
		t.Fatalf("AcceptTCP() error = %v", err)
	case <-time.After(5 * time.Second):
		client.Close()
		t.Fatal("AcceptTCP() timed out")
	}
	return nil, nil
}
