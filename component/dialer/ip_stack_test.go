package dialer

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/component/resolver"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type stackResolver struct {
	resolver.Resolver
	four func(context.Context) ([]netip.Addr, error)
	six  func(context.Context) ([]netip.Addr, error)
}

func (r stackResolver) Invalid() bool { return true }
func (r stackResolver) LookupIPv4(c context.Context, _ string) ([]netip.Addr, error) {
	return r.four(c)
}
func (r stackResolver) LookupIPv6(c context.Context, _ string) ([]netip.Addr, error) { return r.six(c) }
func TestIPStackDialFallsBackWhileFirstFamilyIsStalled(t *testing.T) {
	fourReady := make(chan struct{})
	firstDial := make(chan struct{})
	cancelled := make(chan struct{})
	r := stackResolver{four: func(ctx context.Context) ([]netip.Addr, error) {
		select {
		case <-firstDial:
			close(fourReady)
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, six: func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	}}
	peer1, peer2 := net.Pipe()
	defer peer2.Close()
	opt := option{resolver: r, netDialer: NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "[") {
			close(firstDial)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		}
		return peer1, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := dialWithIPStack(ctx, "tcp", "stack.example:443", opt, resolver.IPQueryDualStack)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(start); elapsed > time.Second || elapsed < 250*time.Millisecond {
		t.Fatalf("fallback took %v", elapsed)
	}
	select {
	case <-fourReady:
	default:
		t.Fatal("alternate lookup never finished")
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("stalled leg leaked")
	}
}
func TestIPStackDialRejectsForbiddenLiteralBeforeSocket(t *testing.T) {
	opt := option{netDialer: NetDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Error("forbidden destination dialed")
		return nil, errors.New("unexpected")
	})}
	for _, tc := range []struct {
		p       resolver.IPQueryPolicy
		address string
	}{{resolver.IPQueryIPv4Only, "[2001:db8::1]:443"}, {resolver.IPQueryIPv6Only, "192.0.2.1:443"}} {
		if _, err := dialWithIPStack(context.Background(), "tcp", tc.address, opt, tc.p); !errors.Is(err, resolver.ErrIPVersion) {
			t.Fatalf("got %v", err)
		}
	}
}

func TestIPStackIPv4LogicalTargetCanUsePhysicalNAT64(t *testing.T) {
	old := DefaultAddressTransform
	defer func() { DefaultAddressTransform = old }()
	DefaultAddressTransform = func(_ string, ip netip.Addr) (netip.Addr, error) {
		if !ip.Is4() {
			t.Fatal("logical target already changed")
		}
		return netip.MustParseAddr("2001:db8::c000:201"), nil
	}
	a, b := net.Pipe()
	defer b.Close()
	opt := option{netDialer: NetDialerFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		if !strings.HasPrefix(address, "[2001:db8:") {
			t.Fatalf("no physical transform: %s", address)
		}
		return a, nil
	})}
	conn, err := dialWithIPStack(context.Background(), "tcp", "192.0.2.1:443", opt, resolver.IPQueryIPv4Only)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
func TestIPStackLateSuccessfulConnectionIsClosed(t *testing.T) {
	lateStarted, releaseLate := make(chan struct{}), make(chan struct{})
	r := stackResolver{four: func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}, six: func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	}}
	winner, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	late, latePeer := net.Pipe()
	defer latePeer.Close()
	opt := option{resolver: r, netDialer: NetDialerFunc(func(ctx context.Context, _ string, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "[") {
			close(lateStarted)
			<-releaseLate
			return late, nil
		}
		select {
		case <-lateStarted:
			return winner, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialWithIPStack(ctx, "tcp", "stack.example:443", opt, resolver.IPQueryDualStack)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	close(releaseLate)
	latePeer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := latePeer.Read(b[:]); err == nil {
		t.Fatal("late socket still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("late socket leaked")
	}
}

func TestIPStackPreferredCancellationCannotReturnBufferedFallback(t *testing.T) {
	for _, prefer := range []int{4, 6} {
		prefer := prefer
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		fallback, peer := net.Pipe()
		opt := option{prefer: prefer}
		dialFn := func(ctx context.Context, _ string, ips []netip.Addr, _ string, _ option) (net.Conn, error) {
			if ips[0].Is4() == (prefer == 4) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			close(ready)
			return fallback, nil
		}
		done := make(chan error, 1)
		go func() {
			conn, err := dualStackDialContext(ctx, dialFn, "tcp", []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, "443", opt)
			if conn != nil {
				conn.Close()
			}
			done <- err
		}()
		<-ready
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("prefer %d returned fallback success after cancellation: %v", prefer, err)
		}
		peer.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := peer.Read(b[:]); err == nil {
			t.Fatal("fallback remained open")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("fallback leaked")
		}
		peer.Close()
	}
}

func TestIPStackFastFailureReleasesAlternateBeforeFallbackTimer(t *testing.T) {
	firstDial := make(chan struct{})
	r := stackResolver{four: func(ctx context.Context) ([]netip.Addr, error) {
		select {
		case <-firstDial:
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, six: func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	}}
	a, b := net.Pipe()
	defer b.Close()
	opt := option{resolver: r, netDialer: NetDialerFunc(func(_ context.Context, _ string, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "[") {
			close(firstDial)
			return nil, errors.New("no route")
		}
		return a, nil
	})}
	started := time.Now()
	conn, err := dialWithIPStack(context.Background(), "tcp", "fast-fail.example:443", opt, resolver.IPQueryDualStack)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if time.Since(started) >= 200*time.Millisecond {
		t.Fatal("fast failure still waited for fallback timer")
	}
}
