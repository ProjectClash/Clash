// Copyright (C) 2023  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package protocol

import (
	"context"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/congestion"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/mathext"
	"github.com/enfein/mieru/v3/pkg/metrics"
	"github.com/enfein/mieru/v3/pkg/protocol/serveruser"
	"github.com/enfein/mieru/v3/pkg/stderror"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	segmentChanCapacity = 256

	segmentTreeCapacity = 4096

	segmentSendQueueTreeCapacity = 1024

	minWindowSize = 16
	maxWindowSize = segmentTreeCapacity

	sessionHeartbeatInterval = 5 * time.Second
	sessionHeartbeatJitterMs = 1000

	minOutputInterval = 1 * time.Millisecond

	backPressureDelay = 100 * time.Microsecond

	packetAckDelay = 1 * time.Millisecond

	retransmissionCheckDelay = 10 * time.Millisecond

	earlyRetransmission = 3
	earlyRetransmissionLimit = 1
	txTimeoutBackOff = 1.5
	maxBackOffDuration = 10 * time.Second
)

type sessionState int32

const (
	sessionInit        sessionState = 0
	sessionAttached    sessionState = 1
	sessionEstablished sessionState = 2
	sessionClosed      sessionState = 3
)

func (ss sessionState) String() string {
	switch ss {
	case sessionInit:
		return "INITIALIZED"
	case sessionAttached:
		return "ATTACHED"
	case sessionEstablished:
		return "ESTABLISHED"
	case sessionClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

type Session struct {
	conn  Underlay
	block atomic.Pointer[cipher.BlockCipher]

	id                uint32
	isClient          bool
	mtu               int
	transportProtocol common.TransportProtocol
	remoteAddr        net.Addr
	state             atomic.Int32
	status            statusCode

	trafficPattern *appctlpb.TrafficPattern

	ready          chan struct{}
	closeRequested atomic.Bool
	closedChan     chan struct{}
	readDeadline   atomic.Int64
	writeDeadline  atomic.Int64
	inputHasErr    atomic.Bool
	inputErr       chan error
	outputHasErr   atomic.Bool
	outputErr      chan error

	sendQueue *segmentTree
	sendBuf   *segmentTree
	recvBuf   *segmentTree
	recvQueue *segmentTree
	recvChan  chan *segment

	packetOutputWakeup chan struct{}

	nextSend               atomic.Uint32
	nextRecv               atomic.Uint32
	lastSend               atomic.Uint32
	lastRXTime             atomic.Int64
	lastTXTime             atomic.Int64
	heartbeatJitter        time.Duration
	nextRetransmissionTime atomic.Int64
	ackOnDataRecv          atomic.Bool
	ackDeadline            atomic.Int64
	unreadBuf              []byte
	bounds                 sessionBounds

	rttStat            *congestion.RTTStats
	cubicSendAlgorithm *congestion.CubicSendAlgorithm
	remoteWindowSize   atomic.Uint32

	wg    sync.WaitGroup
	rLock sync.Mutex
	wLock sync.Mutex
	oLock sync.Mutex

	openSessionRequestSent atomic.Bool

	userName                  atomic.Pointer[string]
	userPolicy                atomic.Pointer[serveruser.Policy]
	pendingServerUserPolicies map[string]serveruser.Policy
	clientUseLowEntropy       atomic.Bool
	uploadBytes               metrics.Metric
	downloadBytes             metrics.Metric
}

var (
	_ net.Conn = (*Session)(nil)

	_ apicommon.UserContext = (*Session)(nil)
)

func NewSession(id uint32, isClient bool, mtu int, users map[string]*appctlpb.User, trafficPattern *appctlpb.TrafficPattern) *Session {
	return newSessionWithServerUserPolicy(id, isClient, mtu, serveruser.Policy{}, serveruser.BuildPolicies(users), trafficPattern)
}

func newSessionWithServerUserPolicy(
	id uint32,
	isClient bool,
	mtu int,
	policy serveruser.Policy,
	pendingPolicies map[string]serveruser.Policy,
	trafficPattern *appctlpb.TrafficPattern,
) *Session {
	rttStat := congestion.NewRTTStats()
	rttStat.SetMaxAckDelay(packetAckDelay)
	rttStat.SetRTOMultiplier(txTimeoutBackOff)
	s := &Session{
		conn:                      nil,
		block:                     atomic.Pointer[cipher.BlockCipher]{},
		id:                        id,
		isClient:                  isClient,
		mtu:                       mtu,
		status:                    statusOK,
		pendingServerUserPolicies: pendingPolicies,
		trafficPattern:            trafficPattern,
		ready:                     make(chan struct{}),
		closedChan:                make(chan struct{}),
		inputErr:                  make(chan error),
		outputErr:                 make(chan error),
		sendQueue:                 newSegmentTree(segmentSendQueueTreeCapacity),
		sendBuf:                   newSegmentTree(segmentTreeCapacity),
		recvBuf:                   newSegmentTree(segmentTreeCapacity),
		recvQueue:                 newSegmentTree(segmentTreeCapacity),
		recvChan:                  make(chan *segment, segmentChanCapacity),
		packetOutputWakeup:        make(chan struct{}, 1),
		bounds:                    newSessionBounds(),
		rttStat:                   rttStat,
		cubicSendAlgorithm:        congestion.NewCubicSendAlgorithm(minWindowSize, maxWindowSize),
	}
	now := time.Now().UnixMicro()
	s.lastRXTime.Store(now)
	s.lastTXTime.Store(now)
	s.heartbeatJitter = randomHeartbeatJitter()
	s.remoteWindowSize.Store(minWindowSize)
	if policy.Name() != "" {
		s.userPolicy.Store(&policy)
	}
	return s
}

func (s *Session) String() string {
	if s.conn == nil {
		return fmt.Sprintf("Session{id=%v}", s.id)
	}
	return fmt.Sprintf("Session{id=%v, local=%v, remote=%v}", s.id, s.LocalAddr(), s.RemoteAddr())
}

func (s *Session) Read(b []byte) (n int, err error) {
	s.rLock.Lock()
	defer s.rLock.Unlock()
	defer func() {
		s.readDeadline.Store(0)
	}()
	if len(b) == 0 {
		return 0, nil
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v trying to read %d bytes", s, len(b))
	}

	var timeC <-chan time.Time
	if readDeadline := s.readDeadline.Load(); readDeadline != 0 {
		timeC = time.After(time.Until(time.UnixMicro(readDeadline)))
	}

	for {
		if len(s.unreadBuf) > 0 {
			copied := copy(b[n:], s.unreadBuf)
			n += copied
			s.taken(copied)
			if copied == len(s.unreadBuf) {
				s.unreadBuf = nil
			} else {
				s.unreadBuf = s.unreadBuf[copied:]
			}
			if n == len(b) || len(s.unreadBuf) > 0 {
				break
			}
		}

		if s.recvQueue.Len() > 0 {
			seg, ok := s.recvQueue.DeleteMin()
			if !ok {
				continue
			}
			if s.isClient && seg.metadata.Protocol() == openSessionResponse && s.isState(sessionAttached) {
				s.forwardStateTo(sessionEstablished)
			}
			copied := copy(b[n:], seg.payload)
			n += copied
			s.taken(copied)
			if copied < len(seg.payload) {
				s.unreadBuf = seg.payload[copied:]
			}
			if n == len(b) {
				break
			}
		} else {
			if n > 0 {
				break
			}

			select {
			case <-s.closedChan:
				return 0, s.closedEnd()
			case <-s.inputErr:
				return 0, s.inputEnded()
			case <-timeC:
				return 0, stderror.ErrTimeout
			case <-s.recvQueue.chanNotEmptyEvent:
			}
		}
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v read %d bytes", s, n)
	}
	if !s.isClient && s.uploadBytes != nil {
		s.uploadBytes.Add(int64(n))
	}
	return n, nil
}

func (s *Session) Write(b []byte) (n int, err error) {
	s.wLock.Lock()
	defer s.wLock.Unlock()

	if s.closeRequested.Load() {
		return 0, io.ErrClosedPipe
	}

	if s.isStateBefore(sessionAttached, false) {
		return 0, fmt.Errorf("%v is not ready for Write()", s)
	}
	if s.isStateAfter(sessionClosed, true) {
		return 0, io.ErrClosedPipe
	}
	defer func() {
		s.writeDeadline.Store(0)
	}()

	if s.isClient && s.isState(sessionAttached) && !s.openSessionRequestSent.Swap(true) {
		s.oLock.Lock()
		seg := &segment{
			metadata: &sessionStruct{
				baseStruct: baseStruct{
					protocol: uint8(openSessionRequest),
				},
				sessionID: s.id,
				seq:       s.nextSend.Load(),
			},
			transport: s.transportProtocol,
		}
		s.nextSend.Add(1)
		_, _, sendLowEntropy := s.lowEntropySendConfig()
		if !sendLowEntropy && len(b) <= MaxSessionOpenPayload {
			seg.metadata.(*sessionStruct).payloadLen = uint16(len(b))
			seg.payload = make([]byte, len(b))
			copy(seg.payload, b)
		}
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v writing %d bytes with open session request", s, len(seg.payload))
		}
		if !s.sendQueue.Insert(seg) {
			s.oLock.Unlock()
			return 0, fmt.Errorf("insert %v to send queue failed", seg)
		} else {
			s.oLock.Unlock()
		}
		if len(seg.payload) > 0 {
			return len(seg.payload), nil
		}
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v writing %d bytes", s, n)
	}
	for len(b) > 0 {
		sizeToSend := mathext.Min(len(b), maxPDU)
		if sent, err := s.writeChunk(b[:sizeToSend]); sent == 0 || err != nil {
			return n, err
		}
		b = b[sizeToSend:]
		n += sizeToSend
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v wrote %d bytes", s, n)
	}
	if !s.isClient && s.downloadBytes != nil {
		s.downloadBytes.Add(int64(n))
	}
	return n, nil
}

func (s *Session) Close() error {
	s.beforeApplicationClose()
	err := s.closeWithError(nil)
	s.afterApplicationClose()
	return err
}

func (s *Session) LocalAddr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return common.NilNetAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	if !common.IsNilNetAddr(s.remoteAddr) {
		return s.remoteAddr
	}
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return common.NilNetAddr()
}

func (s *Session) SetDeadline(t time.Time) error {
	micros := t.UnixMicro()
	if t.IsZero() {
		micros = 0
	}
	s.readDeadline.Store(micros)
	s.writeDeadline.Store(micros)
	return nil
}

func (s *Session) SetReadDeadline(t time.Time) error {
	micros := t.UnixMicro()
	if t.IsZero() {
		micros = 0
	}
	s.readDeadline.Store(micros)
	return nil
}

func (s *Session) SetWriteDeadline(t time.Time) error {
	micros := t.UnixMicro()
	if t.IsZero() {
		micros = 0
	}
	s.writeDeadline.Store(micros)
	return nil
}

func (s *Session) UserName() string {
	if p := s.userName.Load(); p != nil {
		return *p
	}
	return ""
}

func (s *Session) ToSessionInfo() *appctlpb.SessionInfo {
	info := &appctlpb.SessionInfo{
		Id:         proto.String(fmt.Sprintf("%d", s.id)),
		LocalAddr:  proto.String("-"),
		RemoteAddr: proto.String("-"),
		State:      proto.String(sessionState(s.state.Load()).String()),
		RecvQ:      proto.Uint32(uint32(s.recvQueue.Len())),
		RecvBuf:    proto.Uint32(uint32(s.recvBuf.Len())),
		SendQ:      proto.Uint32(uint32(s.sendQueue.Len())),
		SendBuf:    proto.Uint32(uint32(s.sendBuf.Len())),
	}
	if s.conn != nil {
		info.LocalAddr = proto.String(s.conn.LocalAddr().String())
		info.RemoteAddr = proto.String(s.conn.RemoteAddr().String())
		if _, ok := s.conn.(*StreamUnderlay); ok {
			info.Protocol = proto.String("TCP")
			lastRXTime := time.UnixMicro(s.lastRXTime.Load())
			info.LastRecvTime = &timestamppb.Timestamp{
				Seconds: lastRXTime.Unix(),
				Nanos:   int32(lastRXTime.Nanosecond()),
			}
		} else if _, ok := s.conn.(*PacketUnderlay); ok {
			info.Protocol = proto.String("UDP")
			lastRXTime := time.UnixMicro(s.lastRXTime.Load())
			info.LastRecvTime = &timestamppb.Timestamp{
				Seconds: lastRXTime.Unix(),
				Nanos:   int32(lastRXTime.Nanosecond()),
			}
			info.LastRecvSeq = proto.Uint32(uint32(mathext.Max(0, int(s.nextRecv.Load())-1)))
		} else {
			info.Protocol = proto.String("UNKNOWN")
		}
		lastTXTime := time.UnixMicro(s.lastTXTime.Load())
		info.LastSendTime = &timestamppb.Timestamp{
			Seconds: lastTXTime.Unix(),
			Nanos:   int32(lastTXTime.Nanosecond()),
		}
		info.LastSendSeq = proto.Uint32(uint32(mathext.Max(0, int(s.nextSend.Load())-1)))
	}
	return info
}

func (s *Session) isState(target sessionState) bool {
	return sessionState(s.state.Load()) == target
}

func (s *Session) isStateBefore(target sessionState, include bool) bool {
	state := sessionState(s.state.Load())
	if include {
		return state <= target
	} else {
		return state < target
	}
}

func (s *Session) isStateAfter(target sessionState, include bool) bool {
	state := sessionState(s.state.Load())
	if include {
		return state >= target
	} else {
		return state > target
	}
}

func (s *Session) forwardStateTo(next sessionState) {
	for {
		old := s.state.Load()
		if int32(next) <= old {
			return
		}
		if s.state.CompareAndSwap(old, int32(next)) {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v %v => %v", s, sessionState(old), next)
			}
			return
		}
	}
}

func (s *Session) isClientPacketSessionOpening() bool {
	return s.isClient && s.transportProtocol == common.PacketTransport && s.isState(sessionAttached)
}

func (s *Session) isClientPacketSessionOpenResponse(seg *segment) bool {
	return s.isClientPacketSessionOpening() && seg.Protocol() == openSessionResponse
}

func (s *Session) shouldDeferNextPacketData() bool {
	if !s.isClientPacketSessionOpening() {
		return false
	}
	deferData := false
	s.sendQueue.Ascend(func(iter *segment) bool {
		deferData = isDataProtocol(iter.Protocol())
		return false
	})
	return deferData
}

func (s *Session) lowEntropySendConfig() (appctlpb.LowEntropyMode, appctlpb.LowEntropyMaskRotation, bool) {
	mode, rotation, enabled := extractLowEntropyConfig(s.trafficPattern)
	if !enabled {
		return appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, false
	}
	if !s.isClient && !s.clientUseLowEntropy.Load() {
		return appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, false
	}
	return mode, rotation, true
}

func (s *Session) writeChunk(b []byte) (n int, err error) {
	if len(b) > maxPDU {
		return 0, io.ErrShortWrite
	}
	lowEntropyMode, lowEntropyRotation, sendLowEntropy := s.lowEntropySendConfig()

	var timeC <-chan time.Time
	if writeDeadline := s.writeDeadline.Load(); writeDeadline != 0 {
		timeC = time.After(time.Until(time.UnixMicro(writeDeadline)))
	}

	seqBeforeWrite, _ := s.sendQueue.MinSeq()

	nFragment := 1
	fragmentSize, err := maxFragmentSize(s.mtu, s.transportProtocol, lowEntropyMode)
	if err != nil {
		return 0, err
	}
	if len(b) > fragmentSize {
		nFragment = (len(b)-1)/fragmentSize + 1
	}
	for s.sendQueue.Remaining() <= nFragment {
		select {
		case <-s.closedChan:
			return 0, io.EOF
		case <-s.outputErr:
			return 0, io.ErrClosedPipe
		case <-timeC:
			return 0, stderror.ErrTimeout
		default:
		}
		time.Sleep(backPressureDelay)
	}

	s.oLock.Lock()
	ptr := b
	for i := nFragment - 1; i >= 0; i-- {
		select {
		case <-s.closedChan:
			s.oLock.Unlock()
			return 0, io.EOF
		case <-s.outputErr:
			s.oLock.Unlock()
			return 0, io.ErrClosedPipe
		case <-timeC:
			s.oLock.Unlock()
			return 0, stderror.ErrTimeout
		default:
		}
		var protocol protocolType
		if s.isClient {
			protocol = dataClientToServer
			if sendLowEntropy {
				protocol = dataClientToServerLowEntropy
			}
		} else {
			protocol = dataServerToClient
			if sendLowEntropy {
				protocol = dataServerToClientLowEntropy
			}
		}
		partLen := mathext.Min(fragmentSize, len(ptr))
		part := ptr[:partLen]
		payloadLen := uint16(partLen)
		if sendLowEntropy {
			payloadLen, err = lowEntropyEncodedPayloadLen(partLen, lowEntropyMode)
			if err != nil {
				s.oLock.Unlock()
				return 0, err
			}
		}
		das := &dataAckStruct{
			baseStruct: baseStruct{
				protocol: uint8(protocol),
			},
			sessionID:  s.id,
			seq:        s.nextSend.Load(),
			unAckSeq:   s.nextRecv.Load(),
			windowSize: uint16(s.receiveWindowSize()),
			fragment:   uint8(i),
			payloadLen: payloadLen,
		}
		if sendLowEntropy {
			das.lowEntropyMode = uint8(lowEntropyMode)
			das.extractedPayloadLen = uint16(partLen)
			das.lowEntropyMaskRotation = uint8(lowEntropyRotation)
		}
		seg := &segment{
			metadata:  das,
			payload:   make([]byte, partLen),
			transport: s.transportProtocol,
		}
		copy(seg.payload, part)
		s.nextSend.Add(1)
		if !s.sendQueue.Insert(seg) {
			s.oLock.Unlock()
			return 0, fmt.Errorf("insert %v to send queue failed", seg)
		}
		ptr = ptr[partLen:]
	}
	s.oLock.Unlock()

	shouldReturn := false
	for {
		select {
		case <-s.sendQueue.chanEmptyEvent:
			shouldReturn = true
		default:
		}
		if shouldReturn {
			break
		}

		seqAfterWrite, err := s.sendQueue.MinSeq()
		if err != nil || seqAfterWrite > seqBeforeWrite {
			break
		} else {
			time.Sleep(backPressureDelay)
		}
	}

	return len(b), nil
}

func (s *Session) runInputLoop(ctx context.Context) error {
	defer s.listed()()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.closedChan:
			return nil
		case seg := <-s.recvChan:
			if err := s.input(seg); err != nil {
				err = fmt.Errorf("input() failed: %w", err)
				log.Debugf("%v %v", s, err)
				if s.inputHasErr.CompareAndSwap(false, true) {
					close(s.inputErr)
				}
				s.closeWithError(err)
				return err
			}
		}
	}
}

func (s *Session) runOutputLoop(ctx context.Context) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closedChan:
				return nil
			case <-s.sendQueue.chanNotEmptyEvent:
				s.runOutputOnceStream()
			}
		}
	case common.PacketTransport:
		timer := time.NewTimer(s.nextPacketOutputDelay())
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closedChan:
				return nil
			case <-timer.C:
			case <-s.sendQueue.chanNotEmptyEvent:
			case <-s.packetOutputWakeup:
			}
			s.runOutputOncePacket()
			resetTimer(timer, s.nextPacketOutputDelay())
		}
	default:
		err := fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
		log.Debugf("%v %v", s, err)
		if s.outputHasErr.CompareAndSwap(false, true) {
			close(s.outputErr)
		}
		return s.closeWithError(err)
	}
}

func (s *Session) runOutputOnceStream() {
	if s.outputHasErr.Load() {
		time.Sleep(minOutputInterval)
		return
	}

	s.oLock.Lock()
	for {
		seg, ok := s.sendQueue.DeleteMin()
		if !ok {
			s.oLock.Unlock()
			break
		}
		if err := s.output(seg, nil); err != nil {
			err = fmt.Errorf("output() failed: %w", err)
			log.Debugf("%v %v", s, err)
			if s.outputHasErr.CompareAndSwap(false, true) {
				close(s.outputErr)
			}
			s.oLock.Unlock()
			s.closeWithError(err)
			break
		}
	}
}

func (s *Session) runOutputOncePacket() {
	if s.outputHasErr.Load() {
		time.Sleep(minOutputInterval)
		return
	}

	var closeSessionReason error
	hasLoss := false
	hasTimeout := false
	totalTransmissionCount := 0

	if s.sendBuf.Len() > 0 && time.Now().UnixMicro() >= s.nextRetransmissionTime.Load() {
		s.oLock.Lock()
		var nextTX int64 = math.MaxInt64
		s.sendBuf.Ascend(func(iter *segment) bool {
			if iter.txCount >= txCountLimit {
				err := fmt.Errorf("too many retransmission of %v", iter)
				log.Debugf("%v is unhealthy: %v", s, err)
				if s.outputHasErr.CompareAndSwap(false, true) {
					close(s.outputErr)
				}
				closeSessionReason = err
				return false
			}

			satisfyEarlyRetransmission := iter.ackCount >= earlyRetransmission && iter.txCount <= earlyRetransmissionLimit
			if satisfyEarlyRetransmission || time.Now().UnixMicro()-iter.txTime >= iter.txTimeout.Microseconds() {
				if satisfyEarlyRetransmission {
					hasLoss = true
				} else {
					hasTimeout = true
				}
				iter.ackCount = 0
				iter.txCount++
				iter.txTime = time.Now().UnixMicro()
				iter.txTimeout = mathext.Min(s.rttStat.RTO()*time.Duration(math.Pow(txTimeoutBackOff, float64(iter.txCount))), maxBackOffDuration)
				if isDataAckProtocol(iter.metadata.Protocol()) {
					das, _ := toDataAckStruct(iter.metadata)
					das.unAckSeq = s.nextRecv.Load()
				}
				if err := s.output(iter, s.RemoteAddr()); err != nil {
					err = fmt.Errorf("output() failed: %w", err)
					log.Debugf("%v %v", s, err)
					if s.outputHasErr.CompareAndSwap(false, true) {
						close(s.outputErr)
					}
					closeSessionReason = err
					return false
				}
				totalTransmissionCount++
			}
			nextTX = mathext.Min(nextTX, iter.txTime+iter.txTimeout.Microseconds())
			return true
		})
		if nextTX != math.MaxInt64 {
			s.nextRetransmissionTime.Store(nextTX)
		}
		s.oLock.Unlock()
		if closeSessionReason != nil {
			s.closeWithError(closeSessionReason)
		}
		if hasTimeout {
			s.cubicSendAlgorithm.OnTimeout()
		} else if hasLoss {
			s.cubicSendAlgorithm.OnLoss()
		}
	}

	skipSendNewSegment := s.sendWindowSize() <= 0
	if s.sendQueue.Len() > 0 && !skipSendNewSegment {
		s.oLock.Lock()
		for {
			if s.sendBuf.Remaining() <= 1 {
				s.oLock.Unlock()
				break
			}
			if s.shouldDeferNextPacketData() {
				s.oLock.Unlock()
				break
			}

			seg, deleted := s.sendQueue.DeleteMinIf(func(iter *segment) bool {
				return totalTransmissionCount < s.sendWindowSize()
			})
			if !deleted {
				s.oLock.Unlock()
				break
			}

			seg.txCount++
			seg.txTime = time.Now().UnixMicro()
			seg.txTimeout = mathext.Min(s.rttStat.RTO()*time.Duration(math.Pow(txTimeoutBackOff, float64(seg.txCount))), maxBackOffDuration)
			if isDataAckProtocol(seg.metadata.Protocol()) {
				das, _ := toDataAckStruct(seg.metadata)
				das.unAckSeq = s.nextRecv.Load()
			}
			deadline := seg.txTime + seg.txTimeout.Microseconds()
			if s.sendBuf.Len() == 0 {
				s.nextRetransmissionTime.Store(mathext.Min(deadline, seg.txTime+retransmissionCheckDelay.Microseconds()))
			} else if s.nextRetransmissionTime.Load() > deadline {
				s.nextRetransmissionTime.Store(deadline)
			}
			if !s.sendBuf.Insert(seg) {
				s.oLock.Unlock()
				err := fmt.Errorf("output() failed: insert %v to send buffer failed", seg)
				log.Debugf("%v %v", s, err)
				if s.outputHasErr.CompareAndSwap(false, true) {
					close(s.outputErr)
				}
				s.closeWithError(err)
				break
			}
			if err := s.output(seg, s.RemoteAddr()); err != nil {
				s.oLock.Unlock()
				err = fmt.Errorf("output() failed: %w", err)
				log.Debugf("%v %v", s, err)
				if s.outputHasErr.CompareAndSwap(false, true) {
					close(s.outputErr)
				}
				s.closeWithError(err)
				break
			} else {
				totalTransmissionCount++
			}
		}
	}

	now := time.Now().UnixMicro()
	ackDue := s.ackOnDataRecv.Load() && now >= s.ackDeadline.Load()
	jitteredInterval := sessionHeartbeatInterval + s.heartbeatJitter
	exceedHeartbeatInterval := now-s.lastTXTime.Load() > jitteredInterval.Microseconds()
	if !s.isClientPacketSessionOpening() && (ackDue || exceedHeartbeatInterval) {
		s.ackOnDataRecv.Store(false)
		baseStruct := baseStruct{}
		if s.isClient {
			baseStruct.protocol = uint8(ackClientToServer)
		} else {
			baseStruct.protocol = uint8(ackServerToClient)
		}
		s.oLock.Lock()
		ackSeg := &segment{
			metadata: &dataAckStruct{
				baseStruct: baseStruct,
				sessionID:  s.id,
				seq:        uint32(mathext.Max(0, int(s.nextSend.Load())-1)),
				unAckSeq:   s.nextRecv.Load(),
				windowSize: uint16(s.receiveWindowSize()),
			},
			transport: s.transportProtocol}
		err := s.output(ackSeg, s.RemoteAddr())
		s.oLock.Unlock()
		if err != nil {
			err = fmt.Errorf("output() failed: %w", err)
			log.Debugf("%v %v", s, err)
			if s.outputHasErr.CompareAndSwap(false, true) {
				close(s.outputErr)
			}
			s.closeWithError(err)
		}
		s.heartbeatJitter = randomHeartbeatJitter()
	}
}

func (s *Session) nextPacketOutputDelay() time.Duration {
	now := time.Now().UnixMicro()
	var next int64 = math.MaxInt64
	if s.sendBuf.Len() > 0 {
		next = mathext.Min(next, s.nextRetransmissionTime.Load())
	}
	if !s.isClientPacketSessionOpening() {
		if s.ackOnDataRecv.Load() {
			next = mathext.Min(next, s.ackDeadline.Load())
		}
		jitteredInterval := sessionHeartbeatInterval + s.heartbeatJitter
		next = mathext.Min(next, s.lastTXTime.Load()+jitteredInterval.Microseconds())
	}
	if next == math.MaxInt64 {
		return sessionHeartbeatInterval
	}

	delay := time.Duration(next-now) * time.Microsecond
	if delay <= 0 {
		return minOutputInterval
	}
	return delay
}

func (s *Session) wakePacketOutput() {
	select {
	case s.packetOutputWakeup <- struct{}{}:
	default:
	}
}

func (s *Session) requestPacketAck() {
	if s.ackOnDataRecv.Load() {
		return
	}
	s.ackDeadline.Store(time.Now().UnixMicro() + packetAckDelay.Microseconds())
	s.ackOnDataRecv.Store(true)
	s.wakePacketOutput()
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (s *Session) input(seg *segment) error {
	protocol := seg.Protocol()
	if s.isClient {
		if protocol != openSessionResponse && protocol != dataServerToClient && protocol != dataServerToClientLowEntropy && protocol != ackServerToClient && protocol != closeSessionRequest && protocol != closeSessionResponse {
			return stderror.ErrInvalidArgument
		}
	} else {
		if protocol != openSessionRequest && protocol != dataClientToServer && protocol != dataClientToServerLowEntropy && protocol != ackClientToServer && protocol != closeSessionRequest && protocol != closeSessionResponse {
			return stderror.ErrInvalidArgument
		}
	}

	if seg.block != nil {
		if s.block.Load() != nil {
			prevUserName := (*s.block.Load()).BlockContext().UserName
			nextUserName := seg.block.BlockContext().UserName
			if prevUserName == "" {
				panic(fmt.Sprintf("%v cipher block user name is not set", s))
			}
			if nextUserName == "" {
				panic(fmt.Sprintf("%v cipher block user name is not set", seg))
			}
			if prevUserName != nextUserName {
				panic(fmt.Sprintf("%v cipher block user name %q is different from %v cipher block user name %q", s, prevUserName, seg, nextUserName))
			}
		}

		s.block.Store(&seg.block)
		if !s.isClient {
			policy := seg.serverUserPolicy
			if policy.Name() == "" && s.pendingServerUserPolicies != nil {
				policy = s.pendingServerUserPolicies[seg.block.BlockContext().UserName]
			}
			s.pendingServerUserPolicies = nil
			if current := s.userPolicy.Load(); current != nil {
				if current.Name() != seg.block.BlockContext().UserName {
					panic(fmt.Sprintf("%v user policy name %q differs from cipher user name %q", s, current.Name(), seg.block.BlockContext().UserName))
				}
				if policy.Name() != "" && current.Name() != policy.Name() {
					panic(fmt.Sprintf("%v retained user policy name %q differs from segment user policy name %q", s, current.Name(), policy.Name()))
				}
			} else if policy.Name() != "" {
				if policy.Name() != seg.block.BlockContext().UserName {
					panic(fmt.Sprintf("%v user policy name %q differs from cipher user name %q", s, policy.Name(), seg.block.BlockContext().UserName))
				}
				s.userPolicy.Store(&policy)
			}
		}
		if s.UserName() == "" && seg.block.BlockContext().UserName != "" {
			userName := seg.block.BlockContext().UserName
			s.userName.Store(&userName)
		}

		if !s.isClient {
			if s.uploadBytes == nil {
				s.uploadBytes = metrics.RegisterMetric(fmt.Sprintf(metrics.UserMetricGroupFormat, (*s.block.Load()).BlockContext().UserName), metrics.UserMetricUploadBytes, metrics.COUNTER_TIME_SERIES)
			}
			if s.downloadBytes == nil {
				s.downloadBytes = metrics.RegisterMetric(fmt.Sprintf(metrics.UserMetricGroupFormat, (*s.block.Load()).BlockContext().UserName), metrics.UserMetricDownloadBytes, metrics.COUNTER_TIME_SERIES)
			}
		}
	}

	s.lastRXTime.Store(time.Now().UnixMicro())
	if !s.isClient && protocol == dataClientToServerLowEntropy {
		s.clientUseLowEntropy.Store(true)
	}
	if protocol == openSessionRequest || protocol == openSessionResponse || isDataProtocol(protocol) {
		if err := s.inputData(seg); err != nil {
			return err
		}
		if s.isClientPacketSessionOpenResponse(seg) || s.serverDataOpensSession(seg) {
			s.forwardStateTo(sessionEstablished)
			s.wakePacketOutput()
		}
		return nil
	} else if isAckProtocol(protocol) {
		return s.inputAck(seg)
	} else if protocol == closeSessionRequest || protocol == closeSessionResponse {
		return s.inputClose(seg)
	}
	return nil
}

func (s *Session) inputData(seg *segment) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		if s.waitForRecvQueueSpace() {
			if !s.recvQueue.Insert(seg) {
				return fmt.Errorf("inputData() failed: insert %v to receive queue failed", seg)
			}
		}
	case common.PacketTransport:
		das, ok := seg.metadata.(*dataAckStruct)
		if ok {
			unAckSeq := das.unAckSeq
			for {
				seg2, deleted := s.sendBuf.DeleteMinIf(func(iter *segment) bool {
					seq, _ := iter.Seq()
					return seq < unAckSeq
				})
				if !deleted {
					break
				}
				s.rttStat.UpdateRTT(time.Duration(time.Now().UnixMicro()-seg2.txTime) * time.Microsecond)
				s.cubicSendAlgorithm.OnAck()
			}
			s.remoteWindowSize.Store(uint32(das.windowSize))
		}
		if s.sendQueue.Len() > 0 {
			s.wakePacketOutput()
		}

		s.requestPacketAck()
		if s.receiveWindowSize() <= 0 {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v dropped %v because the receive window size is 0", s, seg)
			}
			return nil
		}
		if !s.recvBuf.Insert(seg) {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v dropped %v because insert to receive buffer failed", s, seg)
			}
			return nil
		}

		if s.waitForRecvQueueSpace() {
			if err := s.moveRecvBufToRecvQueue(); err != nil {
				return fmt.Errorf("inputData() failed: %w", err)
			}
		}
		s.requestPacketAck()
	default:
		return fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
	}

	if !s.isClient && seg.metadata.Protocol() == openSessionRequest {
		if s.isState(sessionAttached) {
			s.oLock.Lock()
			if userName := s.UserName(); userName != "" {
				quotaOK, err := s.checkQuota(userName)
				if err != nil {
					log.Debugf("%v checkQuota() failed: %v", s, err)
				}
				if !quotaOK {
					s.status = statusQuotaExhausted
					log.Debugf("Closing %v because user %s used all the quota", s, userName)
					s.oLock.Unlock()
					s.closeWithError(nil)
					return nil
				}
			}
			seg4 := &segment{
				metadata: &sessionStruct{
					baseStruct: baseStruct{
						protocol: uint8(openSessionResponse),
					},
					sessionID: s.id,
					seq:       s.nextSend.Load(),
				},
				transport: s.transportProtocol,
			}
			s.nextSend.Add(1)
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v writing open session response", s)
			}
			if !s.sendQueue.Insert(seg4) {
				s.oLock.Unlock()
				return fmt.Errorf("inputData() failed: insert %v to send queue failed", seg4)
			} else {
				s.oLock.Unlock()
				s.forwardStateTo(sessionEstablished)
			}
		}
	}
	return nil
}

func (s *Session) inputAck(seg *segment) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		return nil
	case common.PacketTransport:
		das := seg.metadata.(*dataAckStruct)
		unAckSeq := das.unAckSeq
		for {
			seg2, deleted := s.sendBuf.DeleteMinIf(func(iter *segment) bool {
				seq, _ := iter.Seq()
				return seq < unAckSeq
			})
			if !deleted {
				break
			}
			s.rttStat.UpdateRTT(time.Duration(time.Now().UnixMicro()-seg2.txTime) * time.Microsecond)
			s.cubicSendAlgorithm.OnAck()
		}
		s.remoteWindowSize.Store(uint32(das.windowSize))

		s.sendBuf.Ascend(func(iter *segment) bool {
			seq, _ := iter.Seq()
			if seq > unAckSeq {
				return false
			}
			if seq == unAckSeq {
				iter.ackCount++
			}
			return true
		})
		if s.sendQueue.Len() > 0 {
			s.wakePacketOutput()
		}
		return nil
	default:
		return fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
	}
}

func (s *Session) inputClose(seg *segment) error {
	s.oLock.Lock()
	if seg.metadata.Protocol() == closeSessionRequest {
		s.notePeerClose(seg)
		seg2 := &segment{
			metadata: &sessionStruct{
				baseStruct: baseStruct{
					protocol: uint8(closeSessionResponse),
				},
				sessionID:  s.id,
				seq:        s.nextSend.Load(),
				statusCode: uint8(statusOK),
				payloadLen: 0,
			},
			transport: s.transportProtocol,
		}
		s.nextSend.Add(1)
		if err := s.output(seg2, s.RemoteAddr()); err != nil {
			s.oLock.Unlock()
			return fmt.Errorf("output() failed: %v", err)
		}
		if seg.metadata.(*sessionStruct).statusCode == uint8(statusQuotaExhausted) {
			log.Infof("Remote requested to shut down the session because user has exhausted quota")
		} else {
			log.Debugf("Remote requested to shut down %v", s)
		}
		s.oLock.Unlock()
		s.closeWithError(nil)
	} else if seg.metadata.Protocol() == closeSessionResponse {
		log.Debugf("Remote received the request from %v to shut down", s)
		s.oLock.Unlock()
		s.closeWithError(nil)
	}
	return nil
}

func (s *Session) output(seg *segment, remoteAddr net.Addr) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		if err := s.conn.(*StreamUnderlay).writeOneSegment(seg); err != nil {
			return fmt.Errorf("TCPUnderlay.writeOneSegment() failed: %v", err)
		}
	case common.PacketTransport:
		err := s.conn.(*PacketUnderlay).writeOneSegment(seg, remoteAddr)
		if err != nil {
			if !stderror.IsNotReady(err) {
				return fmt.Errorf("UDPUnderlay.writeOneSegment() failed: %v", err)
			}
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("UDPUnderlay.writeOneSegment() failed: %v. Will retry later.", err)
			}
			return nil
		}
	default:
		return fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
	}
	seq, _ := seg.Seq()
	s.lastSend.Store(seq)
	s.lastTXTime.Store(time.Now().UnixMicro())
	return nil
}

func (s *Session) closeWithError(err error) error {
	if !s.closeRequested.CompareAndSwap(false, true) {
		return nil
	}

	var gracefulClose bool
	if err == nil {
		log.Debugf("Closing %v", s)
		gracefulClose = true
	} else {
		log.Debugf("Closing %v with error %v", s, err)
	}
	if s.isState(sessionAttached) || s.isState(sessionEstablished) {
		s.oLock.Lock()
		closeRequestSeq := s.nextSend.Load()
		seg := &segment{
			metadata: &sessionStruct{
				baseStruct: baseStruct{
					protocol: uint8(closeSessionRequest),
				},
				sessionID:  s.id,
				seq:        closeRequestSeq,
				statusCode: uint8(s.status),
			},
			transport: s.transportProtocol,
		}
		s.nextSend.Add(1)

		var gracefulCloseSuccess bool
		if gracefulClose {
			if !s.sendQueue.Insert(seg) {
				s.oLock.Unlock()
			} else {
				s.oLock.Unlock()
				for i := 0; i < 1000; i++ {
					time.Sleep(time.Millisecond)
					if s.lastSend.Load() >= closeRequestSeq {
						gracefulCloseSuccess = true
						break
					}
				}
			}
		} else {
			s.oLock.Unlock()
		}
		if !gracefulCloseSuccess {
			s.oLock.Lock()
			if err := s.output(seg, s.RemoteAddr()); err != nil {
				log.Debugf("output() failed: %v", err)
			}
			s.oLock.Unlock()
		}
	}

	s.sendQueue.DeleteAll()
	s.sendBuf.DeleteAll()
	s.forwardStateTo(sessionClosed)
	close(s.closedChan)
	log.Debugf("Closed %v", s)
	metrics.CurrEstablished.Add(-1)
	return nil
}

func (s *Session) sendWindowSize() int {
	return mathext.Max(0, mathext.Min(int(s.cubicSendAlgorithm.CongestionWindowSize())-s.sendBuf.Len(), int(s.remoteWindowSize.Load())))
}

func (s *Session) receiveWindowSize() int {
	return mathext.Max(0, segmentTreeCapacity-s.recvBuf.Len()-s.recvQueue.Len())
}

func (s *Session) waitForRecvQueueSpace() bool {
	for {
		select {
		case <-s.closedChan:
			return false
		default:
		}
		if s.recvQueue.Remaining() > 0 {
			return true
		}
		select {
		case <-s.closedChan:
			return false
		case <-time.After(backPressureDelay):
		}
	}
}

func (s *Session) moveRecvBufToRecvQueue() error {
	for {
		if s.recvQueue.Remaining() <= 0 {
			return nil
		}

		nextRecv := s.nextRecv.Load()
		seg, deleted := s.recvBuf.DeleteMinIf(func(iter *segment) bool {
			seq, _ := iter.Seq()
			return seq <= nextRecv
		})
		if seg == nil || !deleted {
			return nil
		}
		seq, _ := seg.Seq()
		if seq < nextRecv {
			continue
		}
		if !s.recvQueue.Insert(seg) {
			if !s.recvBuf.Insert(seg) {
				return fmt.Errorf("insert %v from receive queue back to receive buffer failed", seg)
			}
			return nil
		}
		s.nextRecv.Add(1)

		das, ok := seg.metadata.(*dataAckStruct)
		if ok {
			s.remoteWindowSize.Store(uint32(das.windowSize))
		}
	}
}

func (s *Session) checkQuota(userName string) (ok bool, err error) {
	policy := s.userPolicy.Load()
	if policy == nil {
		return true, fmt.Errorf("no registered user")
	}
	if policy.Name() != userName {
		return true, fmt.Errorf("user %s is not found", userName)
	}
	if len(policy.Quotas()) == 0 {
		return true, nil
	}

	metricGroupName := fmt.Sprintf(metrics.UserMetricGroupFormat, userName)
	metricGroup := metrics.GetMetricGroupByName(metricGroupName)
	if metricGroup == nil {
		return true, fmt.Errorf("metric group %s is not found", metricGroupName)
	}
	uploadBytes, found := metricGroup.GetMetric(metrics.UserMetricUploadBytes)
	if !found {
		return true, fmt.Errorf("metric %s in group %s is not found", metrics.UserMetricUploadBytes, metricGroupName)
	}
	downloadBytes, found := metricGroup.GetMetric(metrics.UserMetricDownloadBytes)
	if !found {
		return true, fmt.Errorf("metric %s in group %s is not found", metrics.UserMetricDownloadBytes, metricGroupName)
	}
	for _, quota := range policy.Quotas() {
		now := time.Now()
		then := now.Add(-time.Duration(quota.Days()) * 24 * time.Hour)
		totalBytes := uploadBytes.(*metrics.Counter).DeltaBetween(then, now)
		totalBytes += downloadBytes.(*metrics.Counter).DeltaBetween(then, now)
		if totalBytes/1048576 > int64(quota.Megabytes()) {
			return false, nil
		}
	}
	return true, nil
}

func randomHeartbeatJitter() time.Duration {
	jitterMs := mrand.Intn(2*sessionHeartbeatJitterMs+1) - sessionHeartbeatJitterMs
	return time.Duration(jitterMs) * time.Millisecond
}
