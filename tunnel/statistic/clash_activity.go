package statistic

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/metacubex/sing/common"
)

type Activity interface {
	SinceDownload() time.Duration
	SinceUpload() time.Duration
	InboundQueued() (bytes int, known bool)
}

type QueuedSendReporter interface {
	QueuedSendBytes() (bytes int, known bool)
}

type trackerActivity struct {
	lastDownload atomic.Int64
	lastUpload   atomic.Int64
	inbound      atomic.Pointer[inboundRef]
}

type inboundRef struct{ conn net.Conn }

func (a *trackerActivity) start() {
	now := monoNow()
	a.lastDownload.Store(now)
	a.lastUpload.Store(now)
}

func (a *trackerActivity) downloaded(n int64) {
	if n > 0 {
		a.lastDownload.Store(monoNow())
	}
}

func (a *trackerActivity) uploaded(n int64) {
	if n > 0 {
		a.lastUpload.Store(monoNow())
	}
}

func sinceMono(stamp int64) time.Duration {
	if elapsed := monoNow() - stamp; elapsed > 0 {
		return time.Duration(elapsed)
	}
	return 0
}

func (a *trackerActivity) inboundQueued() (int, bool) {
	ref := a.inbound.Load()
	if ref == nil || ref.conn == nil {
		return 0, false
	}
	reporter, ok := common.Cast[QueuedSendReporter](ref.conn)
	if !ok {
		return 0, false
	}
	return reporter.QueuedSendBytes()
}

func (tt *tcpTracker) SinceDownload() time.Duration {
	return sinceMono(tt.activity.lastDownload.Load())
}
func (tt *tcpTracker) SinceUpload() time.Duration { return sinceMono(tt.activity.lastUpload.Load()) }
func (tt *tcpTracker) InboundQueued() (int, bool) { return tt.activity.inboundQueued() }

func (tt *tcpTracker) SetInbound(conn net.Conn) { tt.activity.inbound.Store(&inboundRef{conn: conn}) }

type InboundCloser interface {
	CloseInbound() error
}

func (tt *tcpTracker) CloseInbound() error {
	ref := tt.activity.inbound.Load()
	if ref == nil || ref.conn == nil {
		return nil
	}
	if linger, ok := common.Cast[interface{ SetLinger(int) error }](ref.conn); ok {
		_ = linger.SetLinger(0)
	}
	return ref.conn.Close()
}

func (ut *udpTracker) SinceDownload() time.Duration {
	return sinceMono(ut.activity.lastDownload.Load())
}
func (ut *udpTracker) SinceUpload() time.Duration { return sinceMono(ut.activity.lastUpload.Load()) }

func (ut *udpTracker) InboundQueued() (int, bool) { return 0, false }
