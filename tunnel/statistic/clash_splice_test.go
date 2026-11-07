package statistic_test

import (
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

type spliceTracker interface {
	AttachSplice(splice io.Closer) bool
	DetachSplice()
}

type recordingCloser struct{ closed int }

func (c *recordingCloser) Close() error { c.closed++; return nil }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
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

func TestATrackerTakesOneSpliceAndClosingItEndsTheSplice(t *testing.T) {
	client, server := tcpPair(t)
	tracked := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.NewManagerForTest(), &C.Metadata{}, nil, 0, 0, true)
	tracker, isTracker := any(tracked).(spliceTracker)
	if !isTracker {
		t.Fatal("a tracker does not take a splice")
	}
	splice := &recordingCloser{}
	if !tracker.AttachSplice(splice) {
		t.Fatal("a fresh tracker refused a splice")
	}
	if tracker.AttachSplice(&recordingCloser{}) {
		t.Fatal("a spliced tracker took a second splice")
	}
	if err := tracked.Close(); err != nil || splice.closed != 1 {
		t.Fatalf("Close while spliced = %v, splice closed %d times; want the splice ended once", err, splice.closed)
	}
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatalf("Close while spliced closed the socket the engine holds: %v", err)
	}
	tracker.DetachSplice()
	if err := tracked.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("a detached tracker's Close left the socket open")
	}
	if tracker.AttachSplice(&recordingCloser{}) {
		t.Fatal("a closed tracker took a splice")
	}
	_ = server
}

func TestATrackerIsNotARawSocket(t *testing.T) {
	client, _ := tcpPair(t)
	tracked := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.NewManagerForTest(), &C.Metadata{}, nil, 0, 0, true)
	defer tracked.Close()
	if _, isRaw := any(tracked).(syscall.Conn); isRaw {
		t.Fatal("a tracker is a syscall.Conn")
	}
}
