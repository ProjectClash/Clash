//go:build with_low_memory

package tunnel

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

type quotaTracker struct {
	statistic.Tracker
	info    *statistic.TrackerInfo
	idle    time.Duration
	closed  atomic.Int32
	release func()
}

func newQuotaTracker(network C.NetWork, idle time.Duration, release func()) *quotaTracker {
	return &quotaTracker{
		info:    &statistic.TrackerInfo{UUID: utils.NewUUIDV4(), Metadata: &C.Metadata{NetWork: network}},
		idle:    idle,
		release: release,
	}
}

func (q *quotaTracker) ID() string                   { return q.info.UUID.String() }
func (q *quotaTracker) Info() *statistic.TrackerInfo { return q.info }
func (q *quotaTracker) SinceDownload() time.Duration { return q.idle }
func (q *quotaTracker) SinceUpload() time.Duration   { return q.idle }
func (q *quotaTracker) InboundQueued() (int, bool)   { return 0, false }
func (q *quotaTracker) Close() error {
	if q.closed.Add(1) == 1 && q.release != nil {
		go q.release()
	}
	return nil
}

func withSessionTable(t *testing.T, trackers ...statistic.Tracker) {
	t.Helper()
	prior := sessionTable
	sessionTable = func(f func(statistic.Tracker) bool) {
		for _, tracker := range trackers {
			if !f(tracker) {
				return
			}
		}
	}
	t.Cleanup(func() { sessionTable = prior })
}

func fillTCPSlots(t *testing.T) {
	t.Helper()
	activeTCPConnectionSlots.Store(lowMemoryTCPConnectionAdmissionLimit)
	priorRejected, priorEvicted := rejectedTCPConnectionTotal.Load(), evictedTCPConnectionTotal.Load()
	t.Cleanup(func() {
		activeTCPConnectionSlots.Store(0)
		rejectedTCPConnectionTotal.Store(priorRejected)
		evictedTCPConnectionTotal.Store(priorEvicted)
	})
}

func TestAFullTCPQuotaEvictsTheLongestIdleConnection(t *testing.T) {
	fillTCPSlots(t)
	release := func() { releaseTCPConnectionSlot() }
	idlest := newQuotaTracker(C.TCP, 40*time.Second, release)
	idle := newQuotaTracker(C.TCP, 15*time.Second, release)
	busy := newQuotaTracker(C.TCP, 100*time.Millisecond, release)
	udp := newQuotaTracker(C.UDP, 10*time.Minute, release)
	withSessionTable(t, idle, busy, udp, idlest)

	if !admitTCPConnection() {
		t.Fatal("the new flow was refused while an idle one could make room")
	}
	if idlest.closed.Load() != 1 {
		t.Fatal("the longest-idle TCP flow was not the one let go")
	}
	for _, other := range []*quotaTracker{idle, busy, udp} {
		if other.closed.Load() != 0 {
			t.Fatalf("a second session was closed (idle %v, %v)", other.idle, other.info.Metadata.NetWork)
		}
	}
	snapshot := TCPConnectionAdmissionSnapshot()
	if snapshot.Rejected != rejectedTCPConnectionTotal.Load() || snapshot.Active != lowMemoryTCPConnectionAdmissionLimit {
		t.Fatalf("admission snapshot %+v: the new flow must hold the evicted one's slot", snapshot)
	}
	if snapshot.Evicted == 0 {
		t.Fatalf("the eviction is not counted: %+v", snapshot)
	}
}

func TestAFullTCPQuotaWithNothingIdleRefusesTheNewFlow(t *testing.T) {
	fillTCPSlots(t)
	before := TCPConnectionAdmissionSnapshot()
	busy := newQuotaTracker(C.TCP, tcpEvictMinIdle-time.Second, func() { releaseTCPConnectionSlot() })
	withSessionTable(t, busy)

	if admitTCPConnection() {
		t.Fatal("a flow was admitted over the quota with nothing idle to make room")
	}
	if busy.closed.Load() != 0 {
		t.Fatal("a busy flow was closed")
	}
	after := TCPConnectionAdmissionSnapshot()
	if after.Rejected != before.Rejected+1 || after.Evicted != before.Evicted {
		t.Fatalf("snapshot %+v -> %+v: want exactly one rejection and no eviction", before, after)
	}
}

func fillUDPSlots(t *testing.T) {
	t.Helper()
	activeUDPSessionSlots.Store(lowMemoryUDPSessionLimit)
	priorRejected, priorEvicted := rejectedUDPSessionTotal.Load(), evictedUDPSessionTotal.Load()
	t.Cleanup(func() {
		activeUDPSessionSlots.Store(0)
		rejectedUDPSessionTotal.Store(priorRejected)
		evictedUDPSessionTotal.Store(priorEvicted)
	})
}

func TestAFullUDPQuotaEvictsTheLongestIdleSession(t *testing.T) {
	fillUDPSlots(t)
	release := func() { releaseUDPSessionSlot() }
	idlest := newQuotaTracker(C.UDP, 50*time.Second, release)
	idle := newQuotaTracker(C.UDP, 20*time.Second, release)
	tcp := newQuotaTracker(C.TCP, 10*time.Minute, release)
	withSessionTable(t, idle, tcp, idlest)

	if !acquireUDPSessionSlotEvicting() {
		t.Fatal("the new session was refused while an idle one could make room")
	}
	if idlest.closed.Load() != 1 || idle.closed.Load() != 0 || tcp.closed.Load() != 0 {
		t.Fatalf("closed idlest=%d idle=%d tcp=%d, want only the idlest UDP session", idlest.closed.Load(), idle.closed.Load(), tcp.closed.Load())
	}
	if snapshot := UDPSessionAdmissionSnapshot(); snapshot.Evicted == 0 || snapshot.Active != lowMemoryUDPSessionLimit {
		t.Fatalf("snapshot %+v: the eviction must be counted and the slot taken over", snapshot)
	}
}

func TestAFullUDPQuotaWithNothingIdleRefusesTheNewSession(t *testing.T) {
	fillUDPSlots(t)
	before := UDPSessionAdmissionSnapshot()
	busy := newQuotaTracker(C.UDP, udpEvictMinIdle-time.Second, func() { releaseUDPSessionSlot() })
	withSessionTable(t, busy)

	if acquireUDPSessionSlotEvicting() {
		t.Fatal("a session was admitted over the quota with nothing idle to make room")
	}
	if busy.closed.Load() != 0 {
		t.Fatal("a busy session was closed")
	}
	if after := UDPSessionAdmissionSnapshot(); after.Rejected != before.Rejected+1 {
		t.Fatalf("snapshot %+v -> %+v: want one rejection", before, after)
	}
}

func TestConcurrentEvictionsTakeDifferentVictims(t *testing.T) {
	fillTCPSlots(t)
	release := func() { releaseTCPConnectionSlot() }
	a := newQuotaTracker(C.TCP, 40*time.Second, release)
	b := newQuotaTracker(C.TCP, 30*time.Second, release)
	withSessionTable(t, a, b)

	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- admitTCPConnection() }()
	}
	if !<-results || !<-results {
		t.Fatal("two flows with two idle connections to replace were not both admitted")
	}
	if a.closed.Load() != 1 || b.closed.Load() != 1 {
		t.Fatalf("closed a=%d b=%d; each arrival must take its own victim", a.closed.Load(), b.closed.Load())
	}
}

func TestTheUDPQuotaIsReported(t *testing.T) {
	if snapshot := UDPSessionAdmissionSnapshot(); snapshot.Limit != lowMemoryUDPSessionLimit {
		t.Fatalf("UDP admission limit = %d, want %d", snapshot.Limit, lowMemoryUDPSessionLimit)
	}
}

func TestAFullUDPQuotaAnswersTheNewSessionUnreachable(t *testing.T) {
	fillUDPSlots(t)
	withSessionTable(t)
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		listens.Add(1)
		return nothingPacketConn{}, nil
	}}
	withVerdictTunnel(t, "out", proxy)
	packet := newKeyedPacket(40201)
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
	select {
	case <-packet.reported:
	case <-time.After(3 * time.Second):
		t.Fatal("a session refused by the quota was not answered unreachable")
	}
	if n := listens.Load(); n != 0 {
		t.Fatalf("a refused session opened its outbound %d time(s)", n)
	}
	if active := UDPSessionAdmissionSnapshot().Active; active != lowMemoryUDPSessionLimit {
		t.Fatalf("a refused session changed the active count to %d", active)
	}
}
