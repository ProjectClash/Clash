package xhttp

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type resetTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *resetTrackedConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestAResetClosesThePooledConnectionsAndTheNextStreamDials(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			addr := startReleaseServer(t, mode)
			var mu sync.Mutex
			var dialed []*resetTrackedConn
			dialRaw := func(ctx context.Context) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				tracked := &resetTrackedConn{Conn: raw}
				mu.Lock()
				dialed = append(dialed, tracked)
				mu.Unlock()
				return tracked, nil
			}
			plain := func(_ context.Context, conn net.Conn, _ bool) (net.Conn, error) { return conn, nil }
			makeTransport := func() http.RoundTripper { return NewTransport(dialRaw, plain, nil, nil, 0) }
			cfg := &Config{Host: "example.com", Path: "/release", Mode: mode,
				ReuseConfig: &ReuseConfig{MaxConnections: "3", HMaxRequestTimes: "600-900", HMaxReusableSecs: "1800-3000"}}
			client, err := NewClient(cfg, makeTransport, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if !client.Reuses() {
				t.Fatal("a client with reuse settings does not reuse")
			}
			echo := func() {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := client.Dial(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				var buf [4]byte
				if _, err := io.ReadFull(conn, buf[:]); err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Time{})
			}
			count := func() int { mu.Lock(); defer mu.Unlock(); return len(dialed) }

			echo()
			echo()
			pooled := count()
			client.Reset()
			mu.Lock()
			old := append([]*resetTrackedConn(nil), dialed...)
			mu.Unlock()
			for i, conn := range old {
				if !conn.closed.Load() {
					t.Errorf("pooled connection %d of %d is still open after the reset", i+1, len(old))
				}
			}
			echo()
			if count() == pooled {
				t.Fatalf("the stream after the reset dialed nothing: it went onto a pooled connection (%d dials)", pooled)
			}
		})
	}
}

func TestAResetDuringADialClosesWhatTheDialOpens(t *testing.T) {
	addr := startReleaseServer(t, "stream-one")
	hold := make(chan struct{})
	var dialed atomic.Pointer[resetTrackedConn]
	dialRaw := func(ctx context.Context) (net.Conn, error) {
		<-hold
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		tracked := &resetTrackedConn{Conn: raw}
		dialed.Store(tracked)
		return tracked, nil
	}
	plain := func(_ context.Context, conn net.Conn, _ bool) (net.Conn, error) { return conn, nil }
	makeTransport := func() http.RoundTripper { return NewTransport(dialRaw, plain, nil, nil, 0) }
	client, err := NewClient(&Config{Host: "example.com", Path: "/release", Mode: "stream-one",
		ReuseConfig: &ReuseConfig{MaxConnections: "3"}}, makeTransport, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	type result struct {
		conn net.Conn
		err  error
	}
	got := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.Dial(ctx)
		got <- result{conn, err}
	}()
	time.Sleep(100 * time.Millisecond)
	client.Reset()
	close(hold)
	r := <-got
	if r.err != nil {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if conn := dialed.Load(); conn == nil || conn.closed.Load() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("the stream failed with the reset (%v), and the connection its dial opened is still open", r.err)
	}
	_ = r.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.conn.Write([]byte("ping")); err == nil {
		var buf [4]byte
		_, _ = io.ReadFull(r.conn, buf[:])
	}
	_ = r.conn.SetDeadline(time.Time{})
	_ = r.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn := dialed.Load(); conn != nil && conn.closed.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the connection the dial opened after the reset is still open after its stream closed")
}

func TestADialThatCompletesAfterItsStreamGaveUpIsClosed(t *testing.T) {
	addr := startReleaseServer(t, "stream-one")
	hold := make(chan struct{})
	var dialed atomic.Pointer[resetTrackedConn]
	dialRaw := func(ctx context.Context) (net.Conn, error) {
		<-hold
		raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		tracked := &resetTrackedConn{Conn: raw}
		dialed.Store(tracked)
		return tracked, nil
	}
	plain := func(_ context.Context, conn net.Conn, _ bool) (net.Conn, error) { return conn, nil }
	makeTransport := func() http.RoundTripper { return NewTransport(dialRaw, plain, nil, nil, 0) }
	client, err := NewClient(&Config{Host: "example.com", Path: "/release", Mode: "stream-one",
		ReuseConfig: &ReuseConfig{MaxConnections: "3"}}, makeTransport, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	gaveUp := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		conn, err := client.Dial(ctx)
		if err == nil {
			_ = conn.Close()
		}
		gaveUp <- err
	}()
	time.Sleep(50 * time.Millisecond)
	client.Reset()
	<-gaveUp
	close(hold)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn := dialed.Load(); conn != nil && conn.closed.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dialed.Load() == nil {
		t.Fatal("the dial never completed")
	}
	t.Fatal("the connection a dial opened after its stream gave up is still open")
}
