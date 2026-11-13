package deadline

import (
	"net"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/ProjectClash/Clash/common/net/packet"
)


type heldPacketConn struct {
	net.PacketConn
	held []byte
}

type heldEnhancePacketConn struct {
	packet.EnhancePacketConn
	held []byte
}

func listenLoopback(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func collected[T any](pointer weak.Pointer[T]) bool {
	for i := 0; i < 10; i++ {
		runtime.GC()
		if pointer.Value() == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestAClosedPacketConnIsNotKeptByItsReadDeadline(t *testing.T) {
	for name, wrap := range map[string]func(net.PacketConn) (net.PacketConn, weak.Pointer[[]byte]){
		"a plain packet connection": func(pc net.PacketConn) (net.PacketConn, weak.Pointer[[]byte]) {
			inner := &heldPacketConn{PacketConn: pc, held: make([]byte, 1<<20)}
			return NewNetPacketConn(inner), weak.Make(&inner.held)
		},
		"one that reads without a copy": func(pc net.PacketConn) (net.PacketConn, weak.Pointer[[]byte]) {
			inner := &heldEnhancePacketConn{EnhancePacketConn: packet.NewEnhancePacketConn(pc), held: make([]byte, 1<<20)}
			return NewNetPacketConn(inner), weak.Make(&inner.held)
		},
	} {
		t.Run(name, func(t *testing.T) {
			wrapped, held := wrap(listenLoopback(t))
			if err := wrapped.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if err := wrapped.Close(); err != nil {
				t.Fatal(err)
			}
			wrapped = nil
			if !collected(held) {
				t.Fatal("a closed connection is still reachable an hour before its read deadline: the deadline's timer holds it")
			}
		})
	}
}

func TestAnOpenPacketConnWithAReadDeadlineIsKept(t *testing.T) {
	inner := &heldPacketConn{PacketConn: listenLoopback(t), held: make([]byte, 1<<20)}
	held := weak.Make(&inner.held)
	wrapped := NewNetPacketConn(inner)
	if err := wrapped.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	inner = nil
	runtime.GC()
	runtime.GC()
	if held.Value() == nil {
		t.Fatal("an open connection was collected while its wrapper is in use")
	}
	runtime.KeepAlive(wrapped)
}

func TestADeadlineSetAfterTheCloseKeepsNothing(t *testing.T) {
	inner := &heldPacketConn{PacketConn: listenLoopback(t), held: make([]byte, 1<<20)}
	held := weak.Make(&inner.held)
	wrapped := NewNetPacketConn(inner)
	inner = nil
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Hour))
	wrapped = nil
	if !collected(held) {
		t.Fatal("a closed connection is kept by a read deadline set after it was closed")
	}
}

func TestAPipeEndIsNotKeptByItsDeadlines(t *testing.T) {
	near, far := Pipe()
	end := near.(*pipe)
	end.readWaitOptions.MTU = 1
	held := weak.Make(end)
	_ = near.SetReadDeadline(time.Now().Add(time.Hour))
	_ = near.SetWriteDeadline(time.Now().Add(time.Hour))
	_ = near.Close()
	_ = far.Close()
	near, far, end = nil, nil, nil
	if !collected(held) {
		t.Fatal("a closed pipe end is still reachable an hour before its deadlines")
	}
}

type heldConn struct {
	net.Conn
	held []byte
}

func TestAClosedConnIsNotKeptByItsReadDeadline(t *testing.T) {
	near, far := net.Pipe()
	t.Cleanup(func() { _ = far.Close() })
	inner := &heldConn{Conn: near, held: make([]byte, 1<<20)}
	held := weak.Make(&inner.held)
	wrapped := NewConn(inner)
	inner = nil
	if err := wrapped.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	wrapped = nil
	if !collected(held) {
		t.Fatal("a closed connection is still reachable an hour before its read deadline: the deadline's timer holds it")
	}
}

func TestClosingAPacketConnEndsAReadThatWaitsOnItsDeadline(t *testing.T) {
	inner := &heldPacketConn{PacketConn: listenLoopback(t), held: make([]byte, 1<<20)}
	held := weak.Make(&inner.held)
	wrapped := NewNetPacketConn(inner)
	inner = nil
	if err := wrapped.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := wrapped.ReadFrom(make([]byte, 64))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a read on a closed connection returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read was still waiting 5 s after its connection was closed")
	}
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Hour))
	_ = wrapped.Close()
	wrapped = nil
	if !collected(held) {
		t.Fatal("a connection closed twice, a deadline set in between, is still reachable")
	}
}

func TestClosingAConnEndsAReadThatWaitsOnItsDeadline(t *testing.T) {
	near, far := net.Pipe()
	t.Cleanup(func() { _ = far.Close() })
	wrapped := NewConn(near)
	if err := wrapped.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := wrapped.Read(make([]byte, 64))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a read on a closed connection returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read was still waiting 5 s after its connection was closed")
	}
}
