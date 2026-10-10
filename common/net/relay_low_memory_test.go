//go:build with_low_memory

package net

import (
	"bytes"
	"errors"
	"io"
	stdnet "net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

const expectedLowMemoryRelayBufferSize = 2 * 1024

func TestRelayCopyChunkedHandshake(t *testing.T) {
	payload := bytes.Repeat([]byte("chunked-handshake"), 4096)
	source := &relayPendingReader{Reader: bufio.NewChunkReader(bytes.NewReader(payload), 16384)}
	var output bytes.Buffer
	n, err := relayCopy(&output, source)
	if err != nil || n != int64(len(payload)) || !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("handshake relay: n=%d output=%d err=%v", n, output.Len(), err)
	}
}

func TestRelayCopyWritesDataBeforeReadError(t *testing.T) {
	for _, readErr := range []error{io.EOF, io.ErrUnexpectedEOF} {
		for _, handshake := range []bool{false, true} {
			source := &relayDataErrorReader{err: readErr}
			var reader io.Reader = source
			if handshake {
				reader = &relayPendingReader{Reader: reader}
			}
			var readBytes, writtenBytes int64
			var output bytes.Buffer
			n, err := relayCopy(&relayWriteCounter{Writer: &output, count: func(n int64) { writtenBytes += n }},
				&relayReadCounter{Reader: reader, count: func(n int64) { readBytes += n }})
			wantErr := readErr
			if readErr == io.EOF {
				wantErr = nil
			}
			if !errors.Is(err, wantErr) || output.String() != "tail" || n != 4 || readBytes != 4 || writtenBytes != 4 || source.calls != 1 {
				t.Errorf("readErr=%v handshake=%v: n=%d output=%q err=%v counters=%d/%d reads=%d", readErr, handshake, n, output.String(), err, readBytes, writtenBytes, source.calls)
			}
		}
	}
}

type relayPendingReader struct{ io.Reader }

func (*relayPendingReader) ReaderReplaceable() bool         { return false }
func (*relayPendingReader) ReaderPossiblyReplaceable() bool { return true }
func (r *relayPendingReader) ReadBuffer(b *buf.Buffer) error {
	return bufio.NewExtendedReader(r.Reader).ReadBuffer(b)
}

type relayDataErrorReader struct {
	err   error
	calls int
}

func (r *relayDataErrorReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 1 {
		return 0, errors.New("read after terminal error")
	}
	return copy(p, "tail"), r.err
}

func TestRelayCopyPreservesReadWaiterAndBufferRequirements(t *testing.T) {
	for _, handshake := range []bool{false, true} {
		source := &relayWaitReader{}
		source.handshake = handshake
		destination := &relayHeadroomWriter{t: t}
		n, err := relayCopy(destination, source)
		if err != nil || n != 4 || destination.String() != "wait" || source.waits != 2 {
			t.Fatalf("handshake=%v: n=%d output=%q waits=%d err=%v", handshake, n, destination.String(), source.waits, err)
		}
		if want := (N.ReadWaitOptions{MTU: 8192, FrontHeadroom: 32, RearHeadroom: 16}); source.options != want {
			t.Fatalf("read waiter options = %+v, want %+v", source.options, want)
		}
	}
}

type relayWaitReader struct {
	options   N.ReadWaitOptions
	waits     int
	handshake bool
}

func (*relayWaitReader) Read([]byte) (int, error)          { return 0, errors.New("native waiter lost") }
func (*relayWaitReader) ReaderMTU() int                    { return 8192 }
func (*relayWaitReader) ReaderReplaceable() bool           { return false }
func (r *relayWaitReader) ReaderPossiblyReplaceable() bool { return r.handshake }
func (r *relayWaitReader) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	r.options = options
	return false
}
func (r *relayWaitReader) WaitReadBuffer() (*buf.Buffer, error) {
	r.waits++
	if r.waits > 1 {
		return nil, io.EOF
	}
	b := r.options.NewBuffer()
	_, _ = b.WriteString("wait")
	r.options.PostReturn(b)
	return b, nil
}

type relayHeadroomWriter struct {
	bytes.Buffer
	t *testing.T
}

func (*relayHeadroomWriter) FrontHeadroom() int { return 32 }
func (*relayHeadroomWriter) RearHeadroom() int  { return 16 }
func (w *relayHeadroomWriter) WriteBuffer(b *buf.Buffer) error {
	defer b.Release()
	if b.Start() != 32 || b.Cap() != 8192+32+16 {
		w.t.Errorf("headroom lost: start=%d cap=%d", b.Start(), b.Cap())
	}
	_, err := w.Write(b.Bytes())
	return err
}

func TestRelayCopyPreservesFallbackBufferRequirements(t *testing.T) {
	source := &relayMTUReader{Reader: strings.NewReader("fallback")}
	destination := &relayHeadroomWriter{t: t}
	n, err := relayCopy(destination, source)
	if err != nil || n != 8 || destination.String() != "fallback" || source.capacity != 8192 {
		t.Fatalf("fallback: n=%d output=%q capacity=%d err=%v", n, destination.String(), source.capacity, err)
	}
}

type relayMTUReader struct {
	io.Reader
	capacity int
}

func (*relayMTUReader) ReaderMTU() int { return 8192 }
func (r *relayMTUReader) Read(p []byte) (int, error) {
	r.capacity = len(p)
	return r.Reader.Read(p)
}

func TestBoundedRelayReaderPreservesSyscallEligibility(t *testing.T) {
	if _, ok := newBoundedRelayReader(strings.NewReader("stream")).(syscall.Conn); ok {
		t.Fatal("plain stream incorrectly became eligible for syscall copy")
	}
	client, server := newRelayTCPPair(t)
	defer client.Close()
	defer server.Close()
	conn, ok := newBoundedRelayReader(server).(syscall.Conn)
	if !ok {
		t.Fatal("TCP stream lost syscall copy eligibility")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := raw.Control(func(uintptr) { called = true }); err != nil || !called {
		t.Fatalf("forwarded raw connection unusable: called=%v error=%v", called, err)
	}
}

func TestRelayUsesBoundedCopyBuffers(t *testing.T) {
	left := &bufferRecordingConn{}
	right := &bufferRecordingConn{}

	Relay(left, right)

	for name, conn := range map[string]*bufferRecordingConn{
		"left":  left,
		"right": right,
	} {
		if got := conn.maximumReadBufferCapacity(); got != expectedLowMemoryRelayBufferSize {
			t.Errorf("%s relay read buffer capacity = %d, want %d", name, got, expectedLowMemoryRelayBufferSize)
		}
	}
}

func TestRelayBoundsReplaceableHandshakeBuffer(t *testing.T) {
	source := &relayReplaceableReader{
		handshake: []byte("handshake-"),
		upstream:  strings.NewReader("payload"),
	}
	if _, err := relayCopy(io.Discard, source); err != nil {
		t.Fatalf("relayCopy() error = %v", err)
	}
	if got := source.maxReadCapacity; got != expectedLowMemoryRelayBufferSize {
		t.Fatalf("replaceable handshake buffer capacity = %d, want %d", got, expectedLowMemoryRelayBufferSize)
	}
}

type bufferRecordingConn struct {
	mu             sync.Mutex
	readCapacities []int
}

func (c *bufferRecordingConn) Read(p []byte) (int, error) {
	c.recordReadCapacity(len(p))
	return 0, io.EOF
}

func (c *bufferRecordingConn) ReadBuffer(buffer *buf.Buffer) error {
	c.recordReadCapacity(buffer.Cap())
	return io.EOF
}

func (*bufferRecordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (*bufferRecordingConn) WriteBuffer(buffer *buf.Buffer) error {
	buffer.Release()
	return nil
}

func (*bufferRecordingConn) Close() error                     { return nil }
func (*bufferRecordingConn) LocalAddr() stdnet.Addr           { return testRelayAddr("local") }
func (*bufferRecordingConn) RemoteAddr() stdnet.Addr          { return testRelayAddr("remote") }
func (*bufferRecordingConn) SetDeadline(time.Time) error      { return nil }
func (*bufferRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*bufferRecordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *bufferRecordingConn) recordReadCapacity(capacity int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readCapacities = append(c.readCapacities, capacity)
}

func (c *bufferRecordingConn) maximumReadBufferCapacity() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var maximum int
	for _, capacity := range c.readCapacities {
		if capacity > maximum {
			maximum = capacity
		}
	}
	return maximum
}

type testRelayAddr string

func (a testRelayAddr) Network() string { return string(a) }
func (a testRelayAddr) String() string  { return string(a) }

func TestRelayCopyReleasesDrainedPeekReader(t *testing.T) {
	for _, cached := range []bool{false, true} {
		name := "empty"
		if cached {
			name = "cached"
		}
		t.Run(name, func(t *testing.T) {
			client, server := stdnet.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			source := NewBufferedConn(server)
			payload := bytes.Repeat([]byte("peek-then-stream"), 1024)
			written := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				_ = client.Close()
				written <- err
			}()
			if cached {
				if _, err := source.Peek(1); err != nil {
					t.Fatal(err)
				}
			}
			var output bytes.Buffer
			if _, err := relayCopy(&output, source); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), payload) {
				t.Fatal("relay lost or duplicated payload")
			}
			if source.r != nil {
				t.Fatalf("drained handshake reader retained %d bytes after streaming", source.r.Size())
			}
		})
	}
}

func TestRelayCopyDropsPeekBufferBeforeLiveRead(t *testing.T) {
	for _, cached := range []bool{false, true} {
		name := "empty"
		if cached {
			name = "cached"
		}
		t.Run(name, func(t *testing.T) {
			client, server := stdnet.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			gate := &relayReadGateConn{Conn: server, entered: make(chan struct{}), resume: make(chan struct{})}
			var resumeOnce sync.Once
			resume := func() { resumeOnce.Do(func() { close(gate.resume) }) }
			defer resume()
			source := NewBufferedConn(gate)
			payload := bytes.Repeat([]byte("live-stream"), 1024)
			written := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				_ = client.Close()
				written <- err
			}()
			if cached {
				if _, err := source.Peek(1); err != nil {
					t.Fatal(err)
				}
			}
			gate.enabled = true
			var output bytes.Buffer
			copied := make(chan error, 1)
			go func() { _, err := relayCopy(&output, source); copied <- err }()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("relay did not reach live read")
			}
			if source.r != nil {
				t.Error("handshake buffer remained reachable while relay was waiting for data")
			}
			resume()
			if err := <-copied; err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), payload) {
				t.Fatal("relay lost or duplicated payload")
			}
		})
	}
}

type relayReadGateConn struct {
	stdnet.Conn
	enabled bool
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *relayReadGateConn) Read(p []byte) (int, error) {
	if c.enabled {
		c.once.Do(func() { close(c.entered) })
		<-c.resume
	}
	return c.Conn.Read(p)
}
