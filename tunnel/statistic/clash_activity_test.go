package statistic

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
)

type activityTestConn struct {
	N.ExtendedConn
}

func (activityTestConn) Chains() C.Chain               { return C.Chain{"node", "group"} }
func (activityTestConn) ProviderChains() C.Chain       { return nil }
func (activityTestConn) AppendToChains(C.ProxyAdapter) {}
func (activityTestConn) RemoteDestination() string     { return "198.51.100.1:443" }

func newActivityTestTracker(t *testing.T) (*tcpTracker, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
	manager := NewManagerForTest()
	tracker := NewTCPTracker(activityTestConn{N.NewExtendedConn(local)}, manager, &C.Metadata{NetWork: C.TCP}, nil, 0, 0, false)
	return tracker, remote
}

func TestTrackerRecordsWhenItLastCarriedBytesEachWay(t *testing.T) {
	tracker, peer := newActivityTestTracker(t)
	var activity Activity = tracker

	time.Sleep(30 * time.Millisecond)
	idleDown, idleUp := activity.SinceDownload(), activity.SinceUpload()
	if idleDown < 25*time.Millisecond || idleUp < 25*time.Millisecond {
		t.Fatalf("a fresh tracker reports %v/%v idle after 30ms; idle counts from when it was tracked", idleDown, idleUp)
	}

	go func() { _, _ = peer.Write([]byte("x")) }()
	if _, err := tracker.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if got := activity.SinceDownload(); got >= idleDown {
		t.Fatalf("Read did not mark a download: idle %v, was %v", got, idleDown)
	}
	if got := activity.SinceUpload(); got < idleUp {
		t.Fatalf("Read marked an upload: idle %v, was %v", got, idleUp)
	}

	time.Sleep(30 * time.Millisecond)
	idleDown = activity.SinceDownload()
	go func() { _, _ = io.ReadFull(peer, make([]byte, 1)) }()
	if _, err := tracker.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if got := activity.SinceUpload(); got >= idleUp {
		t.Fatalf("Write did not mark an upload: idle %v, was %v", got, idleUp)
	}
	if got := activity.SinceDownload(); got < idleDown {
		t.Fatalf("Write marked a download: idle %v, was %v", got, idleDown)
	}

	time.Sleep(30 * time.Millisecond)
	idleDown, idleUp = activity.SinceDownload(), activity.SinceUpload()
	_, readCounters := tracker.UnwrapReader()
	_, writeCounters := tracker.UnwrapWriter()
	for _, count := range readCounters {
		count(10)
	}
	if got := activity.SinceDownload(); got >= idleDown {
		t.Fatalf("the unwrapped read counter did not mark a download: idle %v, was %v", got, idleDown)
	}
	for _, count := range writeCounters {
		count(10)
	}
	if got := activity.SinceUpload(); got >= idleUp {
		t.Fatalf("the unwrapped write counter did not mark an upload: idle %v, was %v", got, idleUp)
	}
}

func TestTrackerZeroByteCountIsNotActivity(t *testing.T) {
	tracker, _ := newActivityTestTracker(t)
	time.Sleep(30 * time.Millisecond)
	before := tracker.SinceDownload()
	_, readCounters := tracker.UnwrapReader()
	for _, count := range readCounters {
		count(0)
	}
	if got := tracker.SinceDownload(); got < before {
		t.Fatalf("a zero-byte count marked a download: idle %v, was %v", got, before)
	}
}

type queuedInbound struct {
	net.Conn
	queued int
}

func (c queuedInbound) QueuedSendBytes() (int, bool) { return c.queued, true }

type wrappedInbound struct {
	net.Conn
	upstream net.Conn
}

func (c wrappedInbound) Upstream() any { return c.upstream }

func TestTrackerReadsTheInboundsQueuedBytesThroughWrappers(t *testing.T) {
	tracker, _ := newActivityTestTracker(t)
	if _, known := tracker.InboundQueued(); known {
		t.Fatal("a tracker with no inbound claims to know its queue")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tracker.SetInbound(wrappedInbound{Conn: a, upstream: wrappedInbound{Conn: a, upstream: queuedInbound{Conn: a, queued: 131072}}})
	if queued, known := tracker.InboundQueued(); !known || queued != 131072 {
		t.Fatalf("inbound queue = %d (known %v), want 131072 through two wrappers", queued, known)
	}
	tracker.SetInbound(a)
	if _, known := tracker.InboundQueued(); known {
		t.Fatal("an inbound with no queue reading was reported as known")
	}
}

type activityTestPacketConn struct {
	N.EnhancePacketConn
}

func newActivityPacketConn(conn net.PacketConn) activityTestPacketConn {
	return activityTestPacketConn{N.NewEnhancePacketConn(conn)}
}

func (activityTestPacketConn) Chains() C.Chain                               { return C.Chain{"node"} }
func (activityTestPacketConn) ProviderChains() C.Chain                       { return nil }
func (activityTestPacketConn) AppendToChains(C.ProxyAdapter)                 {}
func (activityTestPacketConn) RemoteDestination() string                     { return "198.51.100.1:443" }
func (activityTestPacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func TestUDPTrackerRecordsActivity(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	tracker := NewUDPTracker(newActivityPacketConn(client), NewManagerForTest(), &C.Metadata{NetWork: C.UDP}, nil, 0, 0, false)

	time.Sleep(30 * time.Millisecond)
	idleDown, idleUp := tracker.SinceDownload(), tracker.SinceUpload()
	if _, err := tracker.WriteTo([]byte("q"), server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if got := tracker.SinceUpload(); got >= idleUp {
		t.Fatalf("WriteTo did not mark an upload: idle %v, was %v", got, idleUp)
	}
	if _, err := server.WriteTo([]byte("a"), client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tracker.ReadFrom(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if got := tracker.SinceDownload(); got >= idleDown {
		t.Fatalf("ReadFrom did not mark a download: idle %v, was %v", got, idleDown)
	}
}

type lingeringInbound struct {
	net.Conn
	linger []int
	closed bool
}

func (c *lingeringInbound) SetLinger(sec int) error { c.linger = append(c.linger, sec); return nil }
func (c *lingeringInbound) Close() error            { c.closed = true; return c.Conn.Close() }

func TestCloseInboundResetsTheAppsSide(t *testing.T) {
	tracker, _ := newActivityTestTracker(t)
	if err := tracker.CloseInbound(); err != nil {
		t.Fatalf("a tracker with no inbound: %v", err)
	}
	a, b := net.Pipe()
	defer b.Close()
	inner := &lingeringInbound{Conn: a}
	tracker.SetInbound(wrappedInbound{Conn: inner, upstream: inner})
	var closer InboundCloser = tracker
	if err := closer.CloseInbound(); err != nil {
		t.Fatal(err)
	}
	if len(inner.linger) != 1 || inner.linger[0] != 0 {
		t.Fatalf("SetLinger calls %v, want one reset (0)", inner.linger)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("the app's side is still open")
	}
}
