package session

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/transport/anytls/padding"
)

func pipeClient(t *testing.T) (*Client, *atomic.Int64) {
	t.Helper()
	scheme := &atomic.Pointer[padding.PaddingFactory]{}
	if !padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, scheme) {
		t.Fatal("the default padding scheme did not parse")
	}
	dials := &atomic.Int64{}
	dialOut := func(context.Context) (net.Conn, error) {
		dials.Add(1)
		local, remote := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, remote)
			_ = remote.Close()
		}()
		return local, nil
	}
	c := NewClient(context.Background(), dialOut, scheme, "", 0, 0, 0, false)
	t.Cleanup(func() { _ = c.Close() })
	return c, dials
}

func idleSessions(c *Client) int {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	return c.idleSession.Len()
}

func heldSessions(c *Client) int {
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	return len(c.sessions)
}

func TestAResetClosesThePooledSessionAndTheNextStreamDialsANewOne(t *testing.T) {
	c, dials := pipeClient(t)
	stream, err := c.CreateStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pooled := stream.(*Stream).sess
	_ = stream.Close()
	if idle := idleSessions(c); idle != 1 || pooled.IsClosed() {
		t.Fatalf("%d idle sessions after the stream closed (closed %v), want the open session pooled", idle, pooled.IsClosed())
	}

	c.Reset()
	if !pooled.IsClosed() {
		t.Fatal("the pooled session survived the reset")
	}
	if idle, held := idleSessions(c), heldSessions(c); idle != 0 || held != 0 {
		t.Fatalf("%d idle and %d held sessions after the reset, want none", idle, held)
	}

	next, err := c.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("a stream after the reset: %v (the reset must leave the client open)", err)
	}
	defer next.Close()
	if dials.Load() != 2 || next.(*Stream).sess == pooled {
		t.Fatalf("dials %d: the stream after the reset did not dial a session of its own", dials.Load())
	}
}

func TestAResetClosesASessionAStreamIsStillOpenOn(t *testing.T) {
	c, dials := pipeClient(t)
	stream, err := c.CreateStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	open := stream.(*Stream).sess

	c.Reset()
	if !open.IsClosed() {
		t.Fatal("the reset left the session a stream is open on")
	}
	if _, err := stream.Write([]byte("after the reset")); err == nil {
		t.Fatal("a stream on a reset session still writes")
	}
	_ = stream.Close()
	if idle, held := idleSessions(c), heldSessions(c); idle != 0 || held != 0 {
		t.Fatalf("%d idle and %d held sessions after the stream closed, want none", idle, held)
	}

	next, err := c.CreateStream(context.Background())
	if err != nil {
		t.Fatalf("a stream after the reset: %v (the reset must leave the client open)", err)
	}
	defer next.Close()
	if dials.Load() != 2 {
		t.Fatalf("dials %d, want the stream after the reset on a session of its own", dials.Load())
	}
}
