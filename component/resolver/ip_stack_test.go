package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type stackTestResolver struct {
	Resolver
	v4 func(context.Context) ([]netip.Addr, error)
	v6 func(context.Context) ([]netip.Addr, error)
}

func (r stackTestResolver) Invalid() bool { return true }
func (r stackTestResolver) LookupIPv4(ctx context.Context, _ string) ([]netip.Addr, error) {
	return r.v4(ctx)
}
func (r stackTestResolver) LookupIPv6(ctx context.Context, _ string) ([]netip.Addr, error) {
	return r.v6(ctx)
}
func TestIPStackConcurrentFirstUsableAndCancellation(t *testing.T) {
	fourStarted, sixStarted, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r := stackTestResolver{v4: func(ctx context.Context) ([]netip.Addr, error) {
		close(fourStarted)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	}, v6: func(ctx context.Context) ([]netip.Addr, error) {
		close(sixStarted)
		select {
		case <-fourStarted:
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := LookupIPWithPolicy(ctx, "stack.example", r, IPQueryDualStack)
	if err != nil || len(got) != 1 || !got[0].Is6() {
		t.Fatalf("got %v, %v", got, err)
	}
	select {
	case <-sixStarted:
	default:
		t.Fatal("AAAA never started")
	}
	select {
	case <-cancelled:
	case <-ctx.Done():
		t.Fatal("losing lookup leaked")
	}
}
func TestIPStackPreferenceWaitsBoth(t *testing.T) {
	for _, p := range []IPQueryPolicy{IPQueryPreferIPv4, IPQueryPreferIPv6} {
		t.Run(p.String(), func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			r := stackTestResolver{v4: func(context.Context) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}, v6: func(ctx context.Context) ([]netip.Addr, error) {
				close(started)
				select {
				case <-release:
					return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan []netip.Addr, 1)
			go func() { got, _ := LookupIPWithPolicy(ctx, "stack.example", r, p); done <- got }()
			<-started
			select {
			case <-done:
				t.Fatal("preference returned before both families completed")
			case <-time.After(15 * time.Millisecond):
			}
			close(release)
			got := <-done
			if len(got) != 2 || got[0].Is4() != (p == IPQueryPreferIPv4) {
				t.Fatalf("wrong preferred order: %v", got)
			}
		})
	}
}
func TestIPStackSingleFamilyNeverQueriesOther(t *testing.T) {
	for _, p := range []IPQueryPolicy{IPQueryIPv4Only, IPQueryIPv6Only} {
		t.Run(p.String(), func(t *testing.T) {
			r := stackTestResolver{v4: func(context.Context) ([]netip.Addr, error) {
				if p == IPQueryIPv6Only {
					t.Error("forbidden A query")
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}, v6: func(context.Context) ([]netip.Addr, error) {
				if p == IPQueryIPv4Only {
					t.Error("forbidden AAAA query")
				}
				return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
			}}
			got, err := LookupIPWithPolicy(context.Background(), "stack.example", r, p)
			if err != nil || len(got) != 1 || got[0].Is4() != (p == IPQueryIPv4Only) {
				t.Fatalf("%v %v", got, err)
			}
		})
	}
}
func TestIPStackEmptyAnswerCannotWin(t *testing.T) {
	emptyReturned, releaseValid := make(chan struct{}), make(chan struct{})
	r := stackTestResolver{v4: func(context.Context) ([]netip.Addr, error) { close(emptyReturned); return nil, nil }, v6: func(ctx context.Context) ([]netip.Addr, error) {
		select {
		case <-releaseValid:
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan []netip.Addr, 1)
	go func() { got, _ := LookupIPWithPolicy(ctx, "stack.example", r, IPQueryDualStack); done <- got }()
	<-emptyReturned
	select {
	case <-done:
		t.Fatal("empty answer won before a usable family existed")
	case <-time.After(15 * time.Millisecond):
	}
	close(releaseValid)
	got := <-done
	if len(got) != 1 || !got[0].Is6() {
		t.Fatalf("%v", got)
	}
}

func TestIPStackCancelledLookupDoesNotReturnPartialSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := stackTestResolver{v4: func(context.Context) ([]netip.Addr, error) { return nil, nil }, v6: func(context.Context) ([]netip.Addr, error) { return nil, nil }}
	_, err := LookupIPWithPolicy(ctx, "stack.example", r, IPQueryPreferIPv6)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestIPStackPreferenceCancellationDuringPartialSuccess(t *testing.T) {
	for _, p := range []IPQueryPolicy{IPQueryPreferIPv4, IPQueryPreferIPv6} {
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan struct{})
		succeeds := func(context.Context) ([]netip.Addr, error) {
			close(ready)
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}
		blocks := func(ctx context.Context) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }
		r := stackTestResolver{v4: succeeds, v6: blocks}
		done := make(chan error, 1)
		go func() { _, err := LookupIPWithPolicy(ctx, "partial.example", r, p); done <- err }()
		<-ready
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("partial result masked cancellation: %v", err)
		}
	}
}
func TestIPStackPreferenceDNSDeadlineKeepsResponsiveFamily(t *testing.T) {
	old := DefaultDNSTimeout
	DefaultDNSTimeout = 25 * time.Millisecond
	defer func() { DefaultDNSTimeout = old }()
	r := stackTestResolver{v4: func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}, v6: func(ctx context.Context) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }}
	got, err := LookupIPWithPolicy(context.Background(), "deadline.example", r, IPQueryPreferIPv6)
	if err != nil || len(got) != 1 || !got[0].Is4() {
		t.Fatalf("responsive family discarded at DNS deadline: %v %v", got, err)
	}
}
