package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)


func TestDualStackCancelsTheLosingLegAtTheWin(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var loserCancelled atomic.Bool
	loserDone := make(chan struct{})

	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			<-ctx.Done()
			loserCancelled.Store(true)
			close(loserDone)
			return nil, ctx.Err()
		}
		return net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := dualStackDialContext(ctx, dialFn,
		"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, port, option{})
	if err != nil {
		t.Fatalf("the reachable leg must win: %v", err)
	}
	if conn == nil {
		t.Fatal("no connection returned")
	}

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("the winning connection is not usable after the race returned: %v", err)
	}
	_ = conn.Close()

	select {
	case <-loserDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the losing leg was still dialling 2s after the win; it should be cancelled at " +
			"the win, not at the caller's deadline")
	}
	if !loserCancelled.Load() {
		t.Fatal("the losing leg ended without being cancelled")
	}
}

func TestDualStackStillReturnsTheFallbackWhenPreferIsSet(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	failure := errors.New("primary refused")
	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			return nil, failure
		}
		return net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}

	conn, err := dualStackDialContext(context.Background(), dialFn,
		"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, port,
		option{prefer: 6})
	if err != nil {
		t.Fatalf("a failed primary must fall back to the non-primary success: %v", err)
	}
	if conn == nil {
		t.Fatal("no connection returned")
	}
	_ = conn.Close()
}

func TestDualStackReturnsBothFailures(t *testing.T) {
	primary := errors.New("v6 refused")
	secondary := errors.New("v4 refused")
	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			return nil, primary
		}
		return nil, secondary
	}

	_, err := dualStackDialContext(context.Background(), dialFn,
		"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, "443", option{})
	if err == nil {
		t.Fatal("both legs failed; an error must be returned")
	}
	if !errors.Is(err, primary) || !errors.Is(err, secondary) {
		t.Fatalf("both failures must be reported, got %v", err)
	}
}

func TestDualStackDoesNotAccumulateChildContexts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) (net.Conn, error) {
		if ips[0].Is6() {
			return nil, errors.New("v6 unreachable")
		}
		return net.Dial("tcp4", net.JoinHostPort("127.0.0.1", port))
	}

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	for i := 0; i < 20; i++ {
		conn, err := dualStackDialContext(parent, dialFn,
			"tcp", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, port, option{})
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("dial %d returned an unusable connection: %v", i, err)
		}
		_ = conn.Close()
	}

	if children := parentChildCount(parent); children != 0 {
		t.Fatalf("20 dials left %d child contexts on a long-lived parent, want 0; each "+
			"uncancelled winner is retained until the parent is cancelled", children)
	}
}

func parentChildCount(parent context.Context) int {
	value := reflect.ValueOf(parent)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	field := value.FieldByName("children")
	if !field.IsValid() {
		return -1
	}
	return field.Len()
}
