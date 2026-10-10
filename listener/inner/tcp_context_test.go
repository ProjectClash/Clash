package inner

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

type contextTestTunnel struct {
	entered chan context.Context
	exited  chan struct{}
	release <-chan struct{}
}

func (t *contextTestTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	t.HandleTCPConnContext(context.Background(), conn, metadata)
}
func (t *contextTestTunnel) HandleTCPConnContext(ctx context.Context, conn net.Conn, _ *C.Metadata) {
	defer close(t.exited)
	defer conn.Close()
	t.entered <- ctx
	select {
	case <-ctx.Done():
	case <-t.release:
	}
}
func (*contextTestTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (*contextTestTunnel) NatTable() C.NatTable                     { return nil }

func TestTCPConnectionCloseCancelsHandler(t *testing.T) {
	New(nil)
	defer func() { CloseTCPConnections(); New(nil) }()
	release := make(chan struct{})
	fake := &contextTestTunnel{make(chan context.Context, 1), make(chan struct{}), release}
	defer func() { close(release); <-fake.exited }()
	conn, err := HandleTcp(fake, "example.invalid:443", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := <-fake.entered
	conn.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("closing internal TCP did not cancel its upstream handler")
	}
}

func TestTCPParentCancellationEndsHandler(t *testing.T) {
	New(nil)
	defer func() { CloseTCPConnections(); New(nil) }()
	fake := &contextTestTunnel{entered: make(chan context.Context, 1), exited: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := HandleTcpContext(ctx, fake, "example.invalid:443", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-fake.entered
	cancel()
	select {
	case <-fake.exited:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not end handler")
	}
}

type drainingTestTunnel struct {
	contextTestTunnel
	canceled chan struct{}
	finish   chan struct{}
}

func (t *drainingTestTunnel) HandleTCPConnContext(ctx context.Context, conn net.Conn, _ *C.Metadata) {
	defer close(t.exited)
	defer conn.Close()
	t.entered <- ctx
	<-ctx.Done()
	close(t.canceled)
	<-t.finish
}

func TestTCPCloseDrainsAndNewStartsAnotherSession(t *testing.T) {
	New(nil)
	defer New(nil)
	fake := &drainingTestTunnel{
		contextTestTunnel: contextTestTunnel{entered: make(chan context.Context, 1), exited: make(chan struct{})},
		canceled:          make(chan struct{}), finish: make(chan struct{}),
	}
	conn, err := HandleTcp(fake, "example.invalid:443", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-fake.entered
	closed := make(chan struct{})
	go func() { CloseTCPConnections(); close(closed) }()
	var finishOnce sync.Once
	finish := func() { finishOnce.Do(func() { close(fake.finish) }) }
	defer func() { finish(); <-closed }()
	select {
	case <-fake.canceled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel handler")
	}
	select {
	case <-closed:
		t.Fatal("shutdown returned before handler finished")
	default:
	}
	if c, err := HandleTcp(fake, "example.invalid:443", ""); err != net.ErrClosed {
		if c != nil {
			c.Close()
		}
		t.Fatalf("new work during shutdown: %v", err)
	}
	finish()
	<-closed
	New(nil)
	restarted := &contextTestTunnel{entered: make(chan context.Context, 1), exited: make(chan struct{})}
	c, err := HandleTcp(restarted, "example.invalid:443", "")
	if err != nil {
		t.Fatal(err)
	}
	<-restarted.entered
	c.Close()
	CloseTCPConnections()
}

type replyTestTunnel struct{ C.Tunnel }

func (replyTestTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) {
	defer conn.Close()
	_, _ = conn.Write([]byte("complete reply"))
}
func TestTCPHandlerCompletionPreservesEOF(t *testing.T) {
	New(nil)
	defer func() { CloseTCPConnections(); New(nil) }()
	conn, err := HandleTcp(replyTestTunnel{}, "example.invalid:443", "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := make([]byte, len("complete reply"))
	_, err = io.ReadFull(conn, data)
	if err != nil {
		t.Fatal(err)
	}
	<-conn.(*tcpConnection).done
	rest, err := io.ReadAll(conn)
	data = append(data, rest...)
	if err != nil || string(data) != "complete reply" {
		t.Fatalf("completed stream: %q, %v", data, err)
	}
}

func TestClosedCoreDoesNotCloseIndependentLegacyTunnel(t *testing.T) {
	New(nil)
	CloseTCPConnections()
	defer New(nil)
	conn, err := HandleTcp(replyTestTunnel{}, "example.invalid:443", "")
	if err != nil {
		t.Fatalf("a separate legacy tunnel inherited the core's shutdown: %v", err)
	}
	defer conn.Close()
	data, err := io.ReadAll(conn)
	if err != nil || string(data) != "complete reply" {
		t.Fatalf("legacy reply: %q %v", data, err)
	}
}
