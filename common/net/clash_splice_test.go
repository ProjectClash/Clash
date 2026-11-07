package net

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/sing/common/network"
)

func tcpPairForSplice(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

func isTCPForSplice(layer any) bool {
	_, isTCP := layer.(*net.TCPConn)
	return isTCP
}

type countingConn struct {
	net.Conn
	reads, writes network.CountFunc
}

func (c *countingConn) UnwrapReader() (io.Reader, []network.CountFunc) {
	return c.Conn, []network.CountFunc{c.reads}
}

func (c *countingConn) UnwrapWriter() (io.Writer, []network.CountFunc) {
	return c.Conn, []network.CountFunc{c.writes}
}

type readCountingConn struct{ net.Conn }

func (c *readCountingConn) UnwrapReader() (io.Reader, []network.CountFunc) {
	return c.Conn, nil
}

type heldConn struct{ net.Conn }

func (c *heldConn) Upstream() any           { return c.Conn }
func (c *heldConn) ReaderReplaceable() bool { return false }
func (c *heldConn) WriterReplaceable() bool { return true }

func TestUnwrapSpliceEndPassesOnlyThroughPassThroughLayers(t *testing.T) {
	client, server := tcpPairForSplice(t)
	if end, ok := UnwrapSpliceEnd(client, isTCPForSplice); !ok || end.Layer != any(client) {
		t.Fatal("a TCP socket is not its own splice end")
	}
	buffered := NewBufferedConn(client)
	if end, ok := UnwrapSpliceEnd(buffered, isTCPForSplice); !ok || end.Layer != any(client) || len(end.Cached) != 0 {
		t.Fatalf("an empty buffered layer: %+v %v", end, ok)
	}

	var read, written int64
	counted := &countingConn{
		Conn:   NewExtendedConn(buffered),
		reads:  func(n int64) { read += n },
		writes: func(n int64) { written += n },
	}
	if _, err := server.Write([]byte("ahead")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffered.Peek(5); err != nil {
		t.Fatal(err)
	}
	end, ok := UnwrapSpliceEnd(counted, isTCPForSplice)
	if !ok || end.Layer != any(client) || len(end.ReadCounters) != 1 || len(end.WriteCounters) != 1 || len(end.Cached) != 1 {
		t.Fatalf("a counted buffered layer holding bytes: %+v %v", end, ok)
	}
	end.ReadCounters[0](3)
	end.WriteCounters[0](5)
	if read != 3 || written != 5 {
		t.Fatalf("counted %d read, %d written; want 3, 5", read, written)
	}
	if cache := end.Cached[0]; cache.Reader != network.CachedReader(buffered) || len(cache.ReadCounters) != 1 {
		t.Fatalf("the cache is %+v", cache)
	}
	if cached := end.Cached[0].Reader.ReadCached(); cached == nil || string(cached.Bytes()) != "ahead" {
		t.Fatal("the cache does not hold what was read ahead")
	}
	if end, ok = UnwrapSpliceEnd(counted, isTCPForSplice); !ok || len(end.Cached) != 0 {
		t.Fatalf("a drained buffered layer: %+v %v", end, ok)
	}

	if _, ok := UnwrapSpliceEnd(&readCountingConn{client}, isTCPForSplice); ok {
		t.Fatal("a layer counting one way was passed")
	}
	if _, ok := UnwrapSpliceEnd(&heldConn{client}, isTCPForSplice); ok {
		t.Fatal("a layer that will not be replaced was passed")
	}
	pipe, other := net.Pipe()
	defer pipe.Close()
	defer other.Close()
	if _, ok := UnwrapSpliceEnd(NewExtendedConn(pipe), isTCPForSplice); ok {
		t.Fatal("a pipe passed for a TCP socket")
	}
}

type closeCounter struct {
	net.Conn
	closed chan struct{}
}

func (c *closeCounter) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return c.Conn.Close()
}

func TestRelayHandsAPairToTheSplicerFirst(t *testing.T) {
	t.Cleanup(func() { SetSplicer(nil) })
	leftApp, left := net.Pipe()
	right, rightRemote := net.Pipe()
	defer leftApp.Close()
	defer rightRemote.Close()
	leftClosed := &closeCounter{Conn: left, closed: make(chan struct{})}
	rightClosed := &closeCounter{Conn: right, closed: make(chan struct{})}
	took := 0
	SetSplicer(func(l, r net.Conn) bool { took++; return true })
	Relay(leftClosed, rightClosed)
	if took != 1 {
		t.Fatalf("the splicer was asked %d times", took)
	}
	for _, closed := range []chan struct{}{leftClosed.closed, rightClosed.closed} {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("a spliced pair was left open")
		}
	}

	SetSplicer(func(net.Conn, net.Conn) bool { return false })
	leftApp2, left2 := net.Pipe()
	right2, rightRemote2 := net.Pipe()
	done := make(chan struct{})
	go func() { Relay(left2, right2); close(done) }()
	go func() { _, _ = leftApp2.Write([]byte("copied")); _ = leftApp2.Close() }()
	buffer := make([]byte, 6)
	if _, err := io.ReadFull(rightRemote2, buffer); err != nil || string(buffer) != "copied" {
		t.Fatalf("a declined pair was not copied: %q %v", buffer, err)
	}
	_ = rightRemote2.Close()
	<-done
}
