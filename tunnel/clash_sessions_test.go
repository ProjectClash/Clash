package tunnel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	icontext "github.com/ProjectClash/Clash/context"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

type holdingGate struct {
	entered chan C.NetWork
	release chan struct{}
}

func newHoldingGate() *holdingGate {
	return &holdingGate{entered: make(chan C.NetWork, 8), release: make(chan struct{})}
}

func (g *holdingGate) wait(ctx context.Context, network C.NetWork) {
	g.entered <- network
	select {
	case <-g.release:
	case <-ctx.Done():
	}
}

func withNewSessionGate(t *testing.T, gate func(context.Context, C.NetWork)) {
	t.Helper()
	SetNewSessionGate(gate)
	t.Cleanup(func() { SetNewSessionGate(nil) })
}

func TestANewTCPFlowWaitsAtTheGateBeforeItDials(t *testing.T) {
	gate := newHoldingGate()
	withNewSessionGate(t, gate.wait)
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, dial: func() (C.Conn, error) { return nil, errRefused }}
	withVerdictTunnel(t, "out", proxy)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		handleTCPConnContext(ctx, icontext.NewConnContext(newVerdictConn(false), tunFlowTo("192.0.2.1")))
	}()
	select {
	case network := <-gate.entered:
		if network != C.TCP {
			t.Fatalf("the gate was asked for %v, want TCP", network)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a new TCP flow never reached the gate")
	}
	time.Sleep(50 * time.Millisecond)
	if dials := proxy.dials.Load(); dials != 0 {
		t.Fatalf("the flow dialled %d time(s) while the gate held it", dials)
	}
	close(gate.release)
	<-done
	if proxy.dials.Load() == 0 {
		t.Fatal("the flow never dialled after the gate let it go")
	}
}

func TestANewUDPSessionWaitsAtTheGateBeforeItOpens(t *testing.T) {
	gate := newHoldingGate()
	withNewSessionGate(t, gate.wait)
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		listens.Add(1)
		return nothingPacketConn{}, nil
	}}
	withVerdictTunnel(t, "out", proxy)

	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(newKeyedPacket(40101), metadata))
	select {
	case network := <-gate.entered:
		if network != C.UDP {
			t.Fatalf("the gate was asked for %v, want UDP", network)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a new UDP session never reached the gate")
	}
	time.Sleep(50 * time.Millisecond)
	if n := listens.Load(); n != 0 {
		t.Fatalf("the session opened %d time(s) while the gate held it", n)
	}
	close(gate.release)
	deadline := time.Now().Add(3 * time.Second)
	for listens.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the session never opened after the gate let it go")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type keyedPacket struct {
	*reportingPacket
	port int
}

func newKeyedPacket(port int) keyedPacket { return keyedPacket{newReportingPacket(), port} }

func (p keyedPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(172, 19, 0, 2), Port: p.port}
}

func TestPacketsOfAnOpenUDPSessionDoNotWait(t *testing.T) {
	var asked atomic.Int32
	withNewSessionGate(t, func(context.Context, C.NetWork) { asked.Add(1) })
	remote, peer := net.Pipe()
	session := blockingPacketConn{nothingConn: nothingConn{N.NewExtendedConn(remote)}, closed: make(chan struct{}), once: &sync.Once{}}
	t.Cleanup(func() { _ = session.Close(); _ = remote.Close(); _ = peer.Close() })
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		return session, nil
	}}
	withVerdictTunnel(t, "out", proxy)
	for i := 0; i < 3; i++ {
		metadata := tunFlowTo("192.0.2.1")
		metadata.NetWork = C.UDP
		handleUDPConn(C.NewPacketAdapter(newKeyedPacket(40102), metadata))
	}
	time.Sleep(100 * time.Millisecond)
	if n := asked.Load(); n != 1 {
		t.Fatalf("three packets of one session asked the gate %d times, want 1", n)
	}
}

type blockingPacketConn struct {
	nothingConn
	closed chan struct{}
	once   *sync.Once
}

func (c blockingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c blockingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, io.EOF
}
func (c blockingPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	<-c.closed
	return nil, nil, nil, io.EOF
}
func (c blockingPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c blockingPacketConn) LocalAddr() net.Addr                           { return &net.UDPAddr{} }
func (c blockingPacketConn) SetDeadline(time.Time) error                   { return nil }
func (c blockingPacketConn) SetReadDeadline(time.Time) error               { return nil }
func (c blockingPacketConn) SetWriteDeadline(time.Time) error              { return nil }
func (c blockingPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

type queuedInbound struct {
	net.Conn
}

func (queuedInbound) QueuedSendBytes() (int, bool) { return 777, true }

type chainConn struct{ N.ExtendedConn }

func (chainConn) Chains() C.Chain               { return C.Chain{"node", "out"} }
func (chainConn) ProviderChains() C.Chain       { return nil }
func (chainConn) AppendToChains(C.ProxyAdapter) {}
func (chainConn) RemoteDestination() string     { return "" }

func TestATrackedFlowCanReadWhatTheAppHasNotTaken(t *testing.T) {
	remote, remotePeer := net.Pipe()
	app, appPeer := net.Pipe()
	t.Cleanup(func() { _ = remote.Close(); _ = remotePeer.Close(); _ = app.Close(); _ = appPeer.Close() })
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, dial: func() (C.Conn, error) {
		return chainConn{N.NewExtendedConn(remote)}, nil
	}}
	withVerdictTunnel(t, "out", proxy)

	metadata := tunFlowTo("192.0.2.77")
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTCPConn(icontext.NewConnContext(queuedInbound{app}, metadata))
	}()
	deadline := time.Now().Add(3 * time.Second)
	var found statistic.Tracker
	for found == nil && time.Now().Before(deadline) {
		statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
			if tracker.Info().Metadata.DstIP == netip.MustParseAddr("192.0.2.77") {
				found = tracker
				return false
			}
			return true
		})
		time.Sleep(10 * time.Millisecond)
	}
	if found == nil {
		t.Fatal("the flow was never tracked")
	}
	activity, ok := found.(statistic.Activity)
	if !ok {
		t.Fatalf("the tracker %T reports no activity", found)
	}
	if queued, known := activity.InboundQueued(); !known || queued != 777 {
		t.Fatalf("the tracker reads %d (known %v) from the app's side, want 777", queued, known)
	}
	_ = remotePeer.Close()
	_ = appPeer.Close()
	<-done
}
