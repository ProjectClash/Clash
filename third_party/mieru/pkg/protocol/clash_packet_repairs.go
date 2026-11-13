package protocol

import (
	"io"
	"sync/atomic"

	"github.com/enfein/mieru/v3/pkg/common"
)

var packetRepairs atomic.Bool

func SetPacketRepairs(on bool) (previous bool) { return packetRepairs.Swap(on) }

func PacketRepairs() bool { return packetRepairs.Load() }

func (s *Session) serverDataOpensSession(seg *segment) bool {
	return packetRepairs.Load() && s.isClientPacketSessionOpening() && isDataProtocol(seg.Protocol())
}

func (s *Session) notePeerClose(seg *segment) {
	if !packetRepairs.Load() || s.transportProtocol != common.PacketTransport {
		return
	}
	if s.closeRequested.Load() {
		return
	}
	if seq, err := seg.Seq(); err == nil && seq > s.nextRecv.Load() {
		s.bounds.peerLeftData.Store(true)
	}
}

func (s *Session) closedEnd() error {
	if s.bounds.peerLeftData.Load() {
		return io.ErrUnexpectedEOF
	}
	return io.EOF
}
