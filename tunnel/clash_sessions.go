package tunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)


var newSessionGate atomic.Pointer[func(ctx context.Context, network C.NetWork)]

func SetNewSessionGate(gate func(ctx context.Context, network C.NetWork)) {
	if gate == nil {
		newSessionGate.Store(nil)
		return
	}
	newSessionGate.Store(&gate)
}

func waitNewSessionGate(ctx context.Context, network C.NetWork) {
	if gate := newSessionGate.Load(); gate != nil {
		(*gate)(ctx, network)
	}
}

func trackInbound(remote C.Conn, inbound net.Conn) {
	if tracker, ok := remote.(interface{ SetInbound(net.Conn) }); ok {
		tracker.SetInbound(inbound)
	}
}

const (
	tcpEvictMinIdle = 10 * time.Second
	udpEvictMinIdle = 5 * time.Second
	evictSettle = time.Second
	evictPoll   = 5 * time.Millisecond
)

var sessionTable = func(f func(statistic.Tracker) bool) { statistic.DefaultManager.Range(f) }

var (
	evictMu sync.Mutex
	evicting = map[string]struct{}{}
)

func evictLongestIdle(network C.NetWork, minIdle time.Duration) bool {
	evictMu.Lock()
	var victim statistic.Tracker
	var victimIdle time.Duration
	sessionTable(func(tracker statistic.Tracker) bool {
		info := tracker.Info()
		if info == nil || info.Metadata == nil || info.Metadata.NetWork != network {
			return true
		}
		activity, ok := tracker.(statistic.Activity)
		if !ok {
			return true
		}
		if _, picked := evicting[tracker.ID()]; picked {
			return true
		}
		idle := activity.SinceDownload()
		if up := activity.SinceUpload(); up < idle {
			idle = up
		}
		if idle >= minIdle && idle > victimIdle {
			victim, victimIdle = tracker, idle
		}
		return true
	})
	if victim == nil {
		evictMu.Unlock()
		return false
	}
	id := victim.ID()
	evicting[id] = struct{}{}
	evictMu.Unlock()

	info := victim.Info()
	log.Infoln("[Memory] quota full: closing %s session %s --> %s, idle %s, to admit a new one",
		network, info.Metadata.SourceDetail(), info.Metadata.RemoteAddress(), victimIdle.Round(time.Second))
	if closer, ok := victim.(statistic.InboundCloser); ok {
		_ = closer.CloseInbound()
	}
	_ = victim.Close()

	evictMu.Lock()
	delete(evicting, id)
	evictMu.Unlock()
	return true
}

func admitTCPConnection() bool {
	if tryAcquireTCPConnectionSlot() {
		return true
	}
	if evictLongestIdle(C.TCP, tcpEvictMinIdle) {
		noteTCPConnectionEvicted()
		if waitForSlot(tryAcquireTCPConnectionSlot) {
			return true
		}
	}
	noteTCPConnectionRejected()
	return false
}

func acquireUDPSessionSlotEvicting() bool {
	if tryAcquireUDPSessionSlot() {
		return true
	}
	if evictLongestIdle(C.UDP, udpEvictMinIdle) {
		noteUDPSessionEvicted()
		if waitForSlot(tryAcquireUDPSessionSlot) {
			return true
		}
	}
	noteUDPSessionRejected()
	return false
}

func waitForSlot(try func() bool) bool {
	deadline := time.Now().Add(evictSettle)
	for {
		if try() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(evictPoll)
	}
}

type quotaSender struct {
	C.PacketSender
	state atomic.Int32
}

const (
	quotaPending int32 = iota
	quotaAdmitted
	quotaClosed
)

func withUDPQuota(maker func() C.PacketSender) func() C.PacketSender {
	return func() C.PacketSender { return &quotaSender{PacketSender: maker()} }
}

func admitUDPSession(ctx context.Context, sender C.PacketSender) bool {
	waitNewSessionGate(ctx, C.UDP)
	quota, ok := sender.(*quotaSender)
	if !ok {
		return true
	}
	if !acquireUDPSessionSlotEvicting() {
		return false
	}
	if !quota.state.CompareAndSwap(quotaPending, quotaAdmitted) {
		releaseUDPSessionSlot()
		return false
	}
	return true
}

func (s *quotaSender) Close() {
	s.PacketSender.Close()
	if s.state.Swap(quotaClosed) == quotaAdmitted {
		releaseUDPSessionSlot()
	}
}
