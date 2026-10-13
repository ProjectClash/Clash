package outbound

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)

type keepingOutbound struct {
	*Direct
	resets  *atomic.Int64
	holding chan struct{}
}

func (k keepingOutbound) ResetNetwork() { k.resets.Add(1) }

func (k keepingOutbound) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if k.holding != nil {
		<-k.holding
	}
	local, remote := net.Pipe()
	_ = remote.Close()
	return NewConn(local, k), nil
}

func (k keepingOutbound) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, k), nil
}

func wrappedKeeping(holding chan struct{}) (C.ProxyAdapter, *atomic.Int64) {
	resets := &atomic.Int64{}
	return NewAutoCloseProxyAdapter(keepingOutbound{Direct: NewDirect(), resets: resets, holding: holding}), resets
}

func probeKind() context.Context {
	return dialer.WithDialKind(context.Background(), dialer.DialKindProbe)
}

func dialed(t *testing.T, node C.ProxyAdapter, ctx context.Context) C.Conn {
	t.Helper()
	c, err := node.DialContext(ctx, &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAProbedNodeIsReleasedWhenNothingUsesIt(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	_ = dialed(t, node, probeKind()).Close()
	if !ReleaseProbedSession(node) || resets.Load() != 1 {
		t.Fatalf("an idle probed node was not released (resets %d)", resets.Load())
	}
	if ReleaseProbedSession(node) || resets.Load() != 1 {
		t.Fatalf("a node with no session since its release was reset again (resets %d)", resets.Load())
	}
}

func TestANodeInUseIsNotReleased(t *testing.T) {
	holding := make(chan struct{})
	node, resets := wrappedKeeping(holding)
	done := make(chan C.Conn)
	go func() {
		c, _ := node.DialContext(probeKind(), &C.Metadata{})
		done <- c
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !sessionDialing(node) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ReleaseProbedSession(node) {
		t.Fatal("released a node while a dial was in flight through it")
	}
	close(holding)
	c := <-done
	if ReleaseProbedSession(node) {
		t.Fatal("released a node a connection is open on")
	}
	if resets.Load() != 0 {
		t.Fatalf("resets %d, want 0", resets.Load())
	}
	_ = c.Close()
	if !ReleaseProbedSession(node) || resets.Load() != 1 {
		t.Fatalf("a node whose last connection closed was not released (resets %d)", resets.Load())
	}
}

func TestAConnectionClosedTwiceIsUncountedOnce(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	first := dialed(t, node, probeKind())
	second := dialed(t, node, probeKind())
	_ = first.Close()
	_ = first.Close()
	if ReleaseProbedSession(node) || resets.Load() != 0 {
		t.Fatalf("a double Close released a node with a connection still open (resets %d)", resets.Load())
	}
	_ = second.Close()
	if !ReleaseProbedSession(node) {
		t.Fatal("a node with every connection closed was not released")
	}
}

func TestAnOpenPacketConnectionKeepsTheSession(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	pc, err := node.ListenPacketContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second) || resets.Load() != 0 {
		t.Fatalf("released a session a packet connection is open on (resets %d)", resets.Load())
	}
	_ = pc.Close()
	if !ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second) {
		t.Fatal("a session whose packet connection closed was not released after its idle period")
	}
}

type unhookedConn struct{ C.Conn }

type unhookedOutbound struct{ keepingOutbound }

func (u unhookedOutbound) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := u.keepingOutbound.DialContext(ctx, metadata)
	return unhookedConn{c}, err
}

func TestAConnectionTheNodeCannotHookKeepsTheSession(t *testing.T) {
	resets := &atomic.Int64{}
	node := NewAutoCloseProxyAdapter(unhookedOutbound{keepingOutbound{Direct: NewDirect(), resets: resets}})
	_ = dialed(t, node, probeKind()).Close()
	if ReleaseProbedSession(node) || ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second) {
		t.Fatal("released a node whose connection could not be counted")
	}
}

func TestAUserSessionIsReleasedOnlyAfterItsIdlePeriod(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	_ = dialed(t, node, context.Background()).Close()
	idle := 20 * time.Second
	if ReleaseUserSessionIfIdle(node, time.Now(), idle) {
		t.Fatal("a session a user just used was released at once")
	}
	if !ReleaseUserSessionIfIdle(node, time.Now().Add(idle+time.Second), idle) || resets.Load() != 1 {
		t.Fatalf("a user session idle past its period was not released (resets %d)", resets.Load())
	}
}

func TestAStreamingConnectionKeepsItsSessionPastTheIdlePeriod(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	c := dialed(t, node, context.Background())
	defer c.Close()
	if ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), 20*time.Second) || resets.Load() != 0 {
		t.Fatalf("the idle sweep dropped a session a connection is streaming on (resets %d)", resets.Load())
	}
}

func TestTheIdlePeriodRunsFromTheLastConnectionsClose(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	c := dialed(t, node, context.Background())
	wrapped := node.(*autoCloseProxyAdapter)
	wrapped.use.mu.Lock()
	wrapped.use.lastActive = time.Now().Add(-time.Hour)
	wrapped.use.mu.Unlock()
	_ = c.Close()
	if ReleaseUserSessionIfIdle(node, time.Now(), 20*time.Second) || resets.Load() != 0 {
		t.Fatalf("a session was released the moment its hour-long stream closed (resets %d)", resets.Load())
	}
}

func TestAProbeDoesNotDropASessionAUserUses(t *testing.T) {
	node, resets := wrappedKeeping(nil)
	_ = dialed(t, node, context.Background()).Close()
	_ = dialed(t, node, probeKind()).Close()
	if ReleaseProbedSession(node) || resets.Load() != 0 {
		t.Fatalf("a probe dropped a session a user used (resets %d)", resets.Load())
	}
}

func TestASessionlessNodeIsLeftAlone(t *testing.T) {
	node := NewAutoCloseProxyAdapter(NewDirect())
	_, _ = node.DialContext(probeKind(), &C.Metadata{Host: "127.0.0.1", DstPort: 1})
	if ReleaseProbedSession(node) || ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second) {
		t.Fatal("released a node that keeps no sessions")
	}
}

type releasingOutbound struct {
	keepingOutbound
	released *atomic.Int64
	declines *atomic.Bool
}

func (r releasingOutbound) ReleaseSessions() bool {
	if r.declines != nil && r.declines.Load() {
		return false
	}
	r.released.Add(1)
	return true
}

func TestAReleaseUsesTheOutboundsOwnReleaseWhenItHasOne(t *testing.T) {
	resets, released := &atomic.Int64{}, &atomic.Int64{}
	node := NewAutoCloseProxyAdapter(releasingOutbound{keepingOutbound{Direct: NewDirect(), resets: resets}, released, nil})
	_ = dialed(t, node, probeKind()).Close()
	if !ReleaseProbedSession(node) || released.Load() != 1 || resets.Load() != 0 {
		t.Fatalf("released %d, reset %d: want the outbound's own release, once", released.Load(), resets.Load())
	}
}

func TestAProbeNotesTheNodesItDials(t *testing.T) {
	first, _ := wrappedKeeping(nil)
	second, _ := wrappedKeeping(nil)
	ctx := WithProbeDials(probeKind())
	_ = dialed(t, first, ctx).Close()
	_ = dialed(t, second, ctx).Close()
	_ = dialed(t, first, ctx).Close()
	if got := ProbeDialed(ctx); len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("noted %v, want the two nodes once each", got)
	}
	if ProbeDialed(probeKind()) != nil {
		t.Fatal("a context without the note returned nodes")
	}
}

func TestAMuxedNodeReleasesTheOutboundUnderneathItsOwnWay(t *testing.T) {
	resets, released := &atomic.Int64{}, &atomic.Int64{}
	inner := releasingOutbound{keepingOutbound{Direct: NewDirect(), resets: resets}, released, nil}
	mux := &SingMux{ProxyAdapter: inner}
	mux.ReleaseSessions()
	if released.Load() != 1 || resets.Load() != 0 {
		t.Fatalf("released %d, reset %d: want the inner outbound's own release, once", released.Load(), resets.Load())
	}
}

func TestADeclinedReleaseLeavesTheNodeReleasable(t *testing.T) {
	resets, released, declines := &atomic.Int64{}, &atomic.Int64{}, &atomic.Bool{}
	node := NewAutoCloseProxyAdapter(releasingOutbound{keepingOutbound{Direct: NewDirect(), resets: resets}, released, declines})
	_ = dialed(t, node, probeKind()).Close()
	declines.Store(true)
	if ReleaseProbedSession(node) {
		t.Fatal("a release the outbound declined was reported done")
	}
	declines.Store(false)
	if !ReleaseUserSessionIfIdle(node, time.Now().Add(time.Hour), time.Second) || released.Load() != 1 {
		t.Fatalf("the sweep after a declined release did not release the node (released %d)", released.Load())
	}
}
