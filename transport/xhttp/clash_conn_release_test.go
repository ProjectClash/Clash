package xhttp

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
)

type releaseTrackedConn struct {
	net.Conn
}

func startReleaseServer(t *testing.T, mode string) string {
	t.Helper()
	handler, err := NewServerHandler(ServerOption{
		Config: Config{Path: "/release", Mode: mode, ScStreamUpServerSecs: "0"},
		ConnHandler: func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, Protocols: new(http.Protocols)}
	server.Protocols.SetUnencryptedHTTP2(true)
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return ln.Addr().String()
}

func TestClosedStreamsReleaseTheirConnections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		keepAlive time.Duration
	}{
		{name: "stream-one", mode: "stream-one"},
		{name: "stream-up", mode: "stream-up"},
		{name: "stream-one/no-ping", mode: "stream-one", keepAlive: -1},
		{name: "stream-up/no-ping", mode: "stream-up", keepAlive: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startReleaseServer(t, tc.mode)

			var live, dialed atomic.Int64
			dialRaw := func(ctx context.Context) (net.Conn, error) {
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				tracked := &releaseTrackedConn{Conn: raw}
				live.Add(1)
				dialed.Add(1)
				runtime.SetFinalizer(tracked, func(*releaseTrackedConn) { live.Add(-1) })
				return tracked, nil
			}
			plain := func(_ context.Context, conn net.Conn, _ bool) (net.Conn, error) { return conn, nil }
			makeTransport := func() http.RoundTripper {
				return NewTransport(dialRaw, plain, nil, nil, tc.keepAlive)
			}
			client, err := NewClient(&Config{Host: "example.com", Path: "/release", Mode: tc.mode}, makeTransport, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			const streams = 64
			for i := 0; i < streams; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				conn, err := client.Dial(ctx)
				cancel()
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write([]byte("ping")); err != nil {
					t.Fatalf("write %d: %v", i, err)
				}
				var echo [4]byte
				if _, err := io.ReadFull(conn, echo[:]); err != nil {
					t.Fatalf("read %d: %v", i, err)
				}
				_ = conn.SetDeadline(time.Time{})
				_ = conn.Close()
			}
			if n := dialed.Load(); n < streams {
				t.Fatalf("expected one raw connection per stream without reuse, got %d for %d streams", n, streams)
			}

			const allowed = streams / 8
			deadline := time.Now().Add(3 * time.Second)
			for live.Load() > allowed && time.Now().Before(deadline) {
				runtime.GC()
				time.Sleep(20 * time.Millisecond)
			}
			if left := live.Load(); left > allowed {
				t.Fatalf("%d of %d closed streams still pin their connection 3 s after close (allowed %d)", left, streams, allowed)
			}
		})
	}
}
