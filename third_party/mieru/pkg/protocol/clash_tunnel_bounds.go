package protocol

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/enfein/mieru/v3/pkg/common"
)

var (
	streamReceiveByteLimit    atomic.Int64
	clientSkipsReplayCache    atomic.Bool
	releaseOnApplicationClose atomic.Bool
)

func SetStreamReceiveByteLimit(limit int64) (previous int64) {
	if limit < 0 {
		limit = 0
	}
	return streamReceiveByteLimit.Swap(limit)
}

func StreamReceiveByteLimit() int64 { return streamReceiveByteLimit.Load() }

func SetClientSkipsReplayCache(on bool) (previous bool) { return clientSkipsReplayCache.Swap(on) }

func ClientSkipsReplayCache() bool { return clientSkipsReplayCache.Load() }

func SetReleaseOnApplicationClose(on bool) (previous bool) {
	return releaseOnApplicationClose.Swap(on)
}

func ReleaseOnApplicationClose() bool { return releaseOnApplicationClose.Load() }

func recordsReplay(isClient bool) bool {
	return !isClient || !clientSkipsReplayCache.Load()
}

type sessionBounds struct {
	queued  atomic.Int64
	drained chan struct{}
	alone bool
	closedByApplication atomic.Bool
	released atomic.Bool
	soundAtClose atomic.Bool
	inputReturned atomic.Bool
	peerLeftData atomic.Bool
}

func newSessionBounds() sessionBounds {
	return sessionBounds{drained: make(chan struct{}, 1)}
}

func (s *Session) ReceiveQueuedBytes() int64 {
	if queued := s.bounds.queued.Load(); queued > 0 {
		return queued
	}
	return 0
}

func queuedForApplication(seg *segment) bool {
	if len(seg.payload) == 0 || seg.transport != common.StreamTransport || seg.metadata == nil {
		return false
	}
	protocol := seg.metadata.Protocol()
	return protocol == openSessionRequest || protocol == openSessionResponse || isDataProtocol(protocol)
}

func (s *Session) admitForApplication(seg *segment, underlayDone <-chan struct{}) bool {
	if s.packetSessionOver() {
		return false
	}
	if !queuedForApplication(seg) {
		return true
	}
	if s.bounds.released.Load() {
		return false
	}
	if limit := streamReceiveByteLimit.Load(); limit > 0 && s.bounds.alone {
		for s.bounds.queued.Load() >= limit {
			select {
			case <-s.bounds.drained:
			case <-s.closedChan:
				return false
			case <-underlayDone:
				return false
			}
		}
	}
	s.bounds.queued.Add(int64(len(seg.payload)))
	return true
}

func (s *Session) taken(n int) {
	if n == 0 || s.transportProtocol != common.StreamTransport {
		return
	}
	s.bounds.queued.Add(int64(-n))
	select {
	case s.bounds.drained <- struct{}{}:
	default:
	}
}

func (s *Session) beforeApplicationClose() {
	if releaseOnApplicationClose.Load() && !s.closeRequested.Load() && !s.inputHasErr.Load() {
		s.bounds.soundAtClose.Store(true)
	}
}

func (s *Session) inputEnded() error {
	if s.bounds.peerLeftData.Load() {
		return io.ErrUnexpectedEOF
	}
	if s.bounds.soundAtClose.Load() {
		return io.EOF
	}
	return io.ErrUnexpectedEOF
}

func (s *Session) afterApplicationClose() {
	if !releaseOnApplicationClose.Load() {
		return
	}
	if again := s.bounds.closedByApplication.Swap(true); !again {
		s.closeUnderlayLeftAlone()
	} else {
		s.releaseReceived()
	}
}

func (s *Session) closeUnderlayLeftAlone() {
	stream, ok := s.conn.(*StreamUnderlay)
	if !s.bounds.alone || !ok || stream == nil {
		return
	}
	go func() {
		_ = stream.Close()
		_ = stream.conn.Close()
	}()
}

func (s *Session) releaseReceived() {
	s.bounds.released.Store(true)
	s.recvQueue.DeleteAll()
	s.recvBuf.DeleteAll()
	for drained := false; !drained; {
		select {
		case <-s.recvChan:
		default:
			drained = true
		}
	}
	if s.rLock.TryLock() {
		s.unreadBuf = nil
		s.rLock.Unlock()
	}
	s.bounds.queued.Store(0)
}

const StreamSegmentPayload = maxPDU

var liveSessions sync.Map

func (s *Session) listed() (unlist func()) {
	liveSessions.Store(s, struct{}{})
	return func() {
		liveSessions.Delete(s)
		s.packetInputReturned()
	}
}

func StreamReceiveQueued() (bytes int64, sessions int) {
	liveSessions.Range(func(key, _ any) bool {
		s := key.(*Session)
		if s.transportProtocol != common.StreamTransport {
			return true
		}
		sessions++
		bytes += s.ReceiveQueuedBytes()
		return true
	})
	return bytes, sessions
}

func (s *Session) packetSessionOver() bool {
	if s.transportProtocol != common.PacketTransport || !releaseOnApplicationClose.Load() {
		return false
	}
	if s.bounds.inputReturned.Load() {
		return true
	}
	select {
	case <-s.closedChan:
		return true
	default:
		return false
	}
}

func (s *Session) packetInputReturned() {
	if s.transportProtocol != common.PacketTransport || !releaseOnApplicationClose.Load() {
		return
	}
	s.bounds.inputReturned.Store(true)
	for {
		select {
		case <-s.recvChan:
		default:
			return
		}
	}
}
