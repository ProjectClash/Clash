package net

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type closeTestListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *closeTestListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *closeTestListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *closeTestListener) Addr() net.Addr { return &net.TCPAddr{} }

type closeObservedConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
func awaitCloseTest(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("listener close did not release connection")
	}
}

func TestHandleContextListenerCloseDuringHandshake(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn := &closeObservedConn{Conn: left, done: make(chan struct{})}
	defer conn.Close()
	base := &closeTestListener{connections: make(chan net.Conn, 1), done: make(chan struct{})}
	base.connections <- conn
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	panics := make(chan any, 1)
	listener := NewHandleContextListener(context.Background(), base, func(context.Context, net.Conn) (net.Conn, error) { close(started); <-release; return conn, nil }, func(p any) { panics <- p })
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if c != nil {
			c.Close()
		}
		accepted <- err
	}()
	awaitCloseTest(t, started)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept remained blocked during handshake")
	}
	unblock()
	awaitCloseTest(t, conn.done)
	select {
	case p := <-panics:
		t.Fatalf("late handshake panicked after listener close: %v", p)
	default:
	}
}

func TestHandleContextListenerCloseBeforeAccept(t *testing.T) {
	base := &closeTestListener{connections: make(chan net.Conn), done: make(chan struct{})}
	listener := NewHandleContextListener(context.Background(), base, func(context.Context, net.Conn) (net.Conn, error) { panic("unexpected handshake") }, nil)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after early Close: %v, %v", conn, err)
	}
}
