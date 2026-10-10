// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	tcpMinTimeout = 2 * time.Microsecond

	InitialRTO = time.Second

	maxSegmentsPerWake = 100
)

type handshakeState int

const (
	handshakeSynSent handshakeState = iota
	handshakeSynRcvd
	handshakeCompleted
)

const (
	maxOptionSize = 40
)

type handshake struct {
	ep       *Endpoint
	listenEP *Endpoint
	state    handshakeState
	active   bool
	flags    header.TCPFlags
	ackNum   seqnum.Value

	iss seqnum.Value

	rcvWnd seqnum.Size

	sndWnd seqnum.Size

	mss uint16

	sndWndScale int

	rcvWndScale int

	startTime tcpip.MonotonicTime

	deferAccept time.Duration

	acked bool

	sendSYNOpts header.TCPSynOptions

	sampleRTTWithTSOnly bool

	retransmitTimer *backoffTimer `state:"nosave"`
}

func timerHandler(e *Endpoint, f func() tcpip.Error) func() {
	return func() {
		e.mu.Lock()
		if err := f(); err != nil {
			e.lastErrorMu.Lock()
			if _, isTimeout := err.(*tcpip.ErrTimeout); e.lastError != nil && isTimeout {
				e.hardError = e.lastError
			} else {
				e.hardError = err
			}
			e.lastError = err
			e.lastErrorMu.Unlock()
			e.cleanupLocked()
			e.setEndpointState(StateError)
			e.mu.Unlock()
			e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
			return
		}
		processor := e.protocol.dispatcher.selectProcessor(e.ID)
		e.mu.Unlock()

		if !e.segmentQueue.empty() {
			processor.queueEndpoint(e)
		}
	}
}

func (e *Endpoint) newHandshake() (h *handshake) {
	h = &handshake{
		ep:          e,
		active:      true,
		rcvWnd:      seqnum.Size(e.initialReceiveWindow()),
		rcvWndScale: e.rcvWndScaleForHandshake(),
	}
	h.ep.AssertLockHeld(e)
	h.resetState()
	e.h = h
	e.TSOffset = e.protocol.tsOffset(e.ID.LocalAddress, e.ID.RemoteAddress)
	timer, err := newBackoffTimer(h.ep.stack.Clock(), InitialRTO, MaxRTO, timerHandler(e, h.retransmitHandlerLocked))
	if err != nil {
		panic(fmt.Sprintf("newBackOffTimer(_, %s, %s, _) failed: %s", InitialRTO, MaxRTO, err))
	}
	h.retransmitTimer = timer
	return h
}

func (e *Endpoint) newPassiveHandshake(isn, irs seqnum.Value, opts header.TCPSynOptions, deferAccept time.Duration) (h *handshake) {
	h = e.newHandshake()
	h.resetToSynRcvd(isn, irs, opts, deferAccept)
	return h
}

func FindWndScale(wnd seqnum.Size) int {
	if wnd < 0x10000 {
		return 0
	}

	max := seqnum.Size(math.MaxUint16)
	s := 0
	for wnd > max && s < header.MaxWndScale {
		s++
		max <<= 1
	}

	return s
}

func (h *handshake) resetState() {
	h.state = handshakeSynSent
	h.flags = header.TCPFlagSyn
	h.ackNum = 0
	h.mss = 0
	h.iss = generateSecureISN(h.ep.TransportEndpointInfo.ID, h.ep.stack.Clock(), h.ep.protocol.seqnumSecret)
}

func generateSecureISN(id stack.TransportEndpointID, clock tcpip.Clock, seed [16]byte) seqnum.Value {
	isnHasher := sha256.New()

	_, _ = isnHasher.Write(seed[:])
	_, _ = isnHasher.Write(id.LocalAddress.AsSlice())
	_, _ = isnHasher.Write(id.RemoteAddress.AsSlice())
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, id.LocalPort)
	_, _ = isnHasher.Write(portBuf)
	binary.LittleEndian.PutUint16(portBuf, id.RemotePort)
	_, _ = isnHasher.Write(portBuf)
	hash := binary.LittleEndian.Uint32(isnHasher.Sum(nil)[:4])
	isn := hash + uint32(clock.NowMonotonic().Sub(tcpip.MonotonicTime{}).Nanoseconds()>>6)
	return seqnum.Value(isn)
}

func (h *handshake) effectiveRcvWndScale() uint8 {
	if h.sndWndScale < 0 {
		return 0
	}
	return uint8(h.rcvWndScale)
}

func (h *handshake) resetToSynRcvd(iss seqnum.Value, irs seqnum.Value, opts header.TCPSynOptions, deferAccept time.Duration) {
	h.active = false
	h.state = handshakeSynRcvd
	h.flags = header.TCPFlagSyn | header.TCPFlagAck
	h.iss = iss
	h.ackNum = irs + 1
	h.mss = opts.MSS
	h.sndWndScale = opts.WS
	h.deferAccept = deferAccept
	h.ep.setEndpointState(StateSynRecv)
}

func (h *handshake) checkAck(s *segment) bool {
	return !(s.flags.Contains(header.TCPFlagAck) && s.ackNumber != h.iss+1)
}

func (h *handshake) synSentState(s *segment) tcpip.Error {
	if s.flags.Contains(header.TCPFlagRst) {
		if s.flags.Contains(header.TCPFlagAck) && s.ackNumber == h.iss+1 {
			return &tcpip.ErrConnectionRefused{}
		}
		return nil
	}

	if !h.checkAck(s) {
		h.ep.sendEmptyRaw(header.TCPFlagRst, s.ackNumber, 0, 0)
		h.retransmitTimer.reinit(tcpMinTimeout)
		return nil
	}

	if !s.flags.Contains(header.TCPFlagSyn) {
		return nil
	}

	rcvSynOpts := parseSynSegmentOptions(s)

	h.ep.maybeEnableTimestamp(rcvSynOpts)

	h.ep.maybeEnableSACKPermitted(rcvSynOpts)

	h.ackNum = s.sequenceNumber + 1
	h.flags |= header.TCPFlagAck
	h.mss = rcvSynOpts.MSS
	h.sndWndScale = rcvSynOpts.WS

	if s.flags.Contains(header.TCPFlagAck) {
		h.state = handshakeCompleted
		h.transitionToStateEstablishedLocked(s)

		h.ep.sendEmptyRaw(header.TCPFlagAck, h.iss+1, h.ackNum, h.rcvWnd>>h.effectiveRcvWndScale())
		return nil
	}

	h.state = handshakeSynRcvd
	ttl := calculateTTL(h.ep.route, h.ep.ipv4TTL, h.ep.ipv6HopLimit)
	amss := h.ep.amss
	h.ep.setEndpointState(StateSynRecv)
	synOpts := header.TCPSynOptions{
		WS:    int(h.effectiveRcvWndScale()),
		TS:    rcvSynOpts.TS,
		TSVal: h.ep.tsValNow(),
		TSEcr: h.ep.recentTimestamp(),

		SACKPermitted: rcvSynOpts.SACKPermitted,
		MSS:           amss,
	}
	if ttl == 0 {
		ttl = h.ep.route.DefaultTTL()
	}
	h.ep.sendSynTCP(h.ep.route, tcpFields{
		id:        h.ep.TransportEndpointInfo.ID,
		ttl:       ttl,
		tos:       h.ep.sendTOS,
		flags:     h.flags,
		seq:       h.iss,
		ack:       h.ackNum,
		rcvWnd:    h.rcvWnd,
		df:        h.ep.pmtud == tcpip.PMTUDiscoveryWant || h.ep.pmtud == tcpip.PMTUDiscoveryDo || h.ep.pmtud == tcpip.PMTUDiscoveryProbe,
		expOptVal: h.ep.getExperimentOptionValue(h.ep.route),
	}, synOpts)
	return nil
}

func (h *handshake) synRcvdState(s *segment) tcpip.Error {
	if s.flags.Contains(header.TCPFlagRst) {
		if s.sequenceNumber.InWindow(h.ackNum, h.rcvWnd) {
			return &tcpip.ErrConnectionRefused{}
		}
		return nil
	}

	if !h.checkAck(s) && h.listenEP != nil {
		iss := s.ackNumber - 1
		data, ok := h.listenEP.listenCtx.isCookieValid(s.id, iss, s.sequenceNumber-1)
		if !ok || int(data) >= len(mssTable) {
			h.ep.sendEmptyRaw(header.TCPFlagRst, s.ackNumber, 0, 0)
			return nil
		}
		h.mss = mssTable[data]
		h.iss = iss
	}

	if !s.sequenceNumber.InWindow(h.ackNum, h.rcvWnd) {
		if h.ep.allowOutOfWindowAck() {
			h.ep.sendEmptyRaw(header.TCPFlagAck, h.iss+1, h.ackNum, h.rcvWnd)
		}
		return nil
	}

	if s.flags.Contains(header.TCPFlagSyn) && s.sequenceNumber != h.ackNum-1 {
		ack := s.sequenceNumber.Add(s.logicalLen())
		seq := seqnum.Value(0)
		if s.flags.Contains(header.TCPFlagAck) {
			seq = s.ackNumber
		}
		h.ep.sendEmptyRaw(header.TCPFlagRst|header.TCPFlagAck, seq, ack, 0)

		if !h.active {
			return &tcpip.ErrInvalidEndpointState{}
		}

		h.resetState()
		synOpts := header.TCPSynOptions{
			WS:            h.rcvWndScale,
			TS:            h.ep.SendTSOk,
			TSVal:         h.ep.tsValNow(),
			TSEcr:         h.ep.recentTimestamp(),
			SACKPermitted: h.ep.SACKPermitted,
			MSS:           h.ep.amss,
		}
		h.ep.sendSynTCP(h.ep.route, tcpFields{
			id:        h.ep.TransportEndpointInfo.ID,
			ttl:       calculateTTL(h.ep.route, h.ep.ipv4TTL, h.ep.ipv6HopLimit),
			tos:       h.ep.sendTOS,
			flags:     h.flags,
			seq:       h.iss,
			ack:       h.ackNum,
			rcvWnd:    h.rcvWnd,
			df:        h.ep.pmtud == tcpip.PMTUDiscoveryWant || h.ep.pmtud == tcpip.PMTUDiscoveryDo || h.ep.pmtud == tcpip.PMTUDiscoveryProbe,
			expOptVal: h.ep.getExperimentOptionValue(h.ep.route),
		}, synOpts)
		return nil
	}

	if s.flags.Contains(header.TCPFlagAck) {
		if h.deferAccept != 0 && s.payloadSize() == 0 && h.ep.stack.Clock().NowMonotonic().Sub(h.startTime) < h.deferAccept {
			h.acked = true
			h.ep.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		if h.ep.SendTSOk && !s.parsedOptions.TS {
			h.ep.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		if listenEP := h.listenEP; listenEP != nil && listenEP.acceptQueueIsFull() {
			listenEP.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		if h.ep.SendTSOk && s.parsedOptions.TS {
			h.ep.updateRecentTimestamp(s.parsedOptions.TSVal, h.ackNum, s.sequenceNumber)
		}

		h.state = handshakeCompleted
		h.transitionToStateEstablishedLocked(s)

		if (s.flags.Contains(header.TCPFlagFin) || s.payloadSize() > 0) && h.ep.enqueueSegment(s) {
			h.ep.protocol.dispatcher.selectProcessor(h.ep.ID).queueEndpoint(h.ep)

		}
		return nil
	}

	return nil
}

func (h *handshake) handleSegment(s *segment) tcpip.Error {
	h.sndWnd = s.window
	if !s.flags.Contains(header.TCPFlagSyn) && h.sndWndScale > 0 {
		h.sndWnd <<= uint8(h.sndWndScale)
	}

	switch h.state {
	case handshakeSynRcvd:
		return h.synRcvdState(s)
	case handshakeSynSent:
		return h.synSentState(s)
	}
	return nil
}

func (h *handshake) processSegments() tcpip.Error {
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := h.ep.segmentQueue.dequeue()
		if s == nil {
			return nil
		}

		err := h.handleSegment(s)
		s.DecRef()
		if err != nil {
			return err
		}

		if h.state == handshakeCompleted {
			break
		}
	}

	return nil
}

func (h *handshake) start() {
	h.startTime = h.ep.stack.Clock().NowMonotonic()
	h.ep.amss = calculateAdvertisedMSS(h.ep.userMSS, h.ep.route)
	var sackEnabled tcpip.TCPSACKEnabled
	if err := h.ep.stack.TransportProtocolOption(ProtocolNumber, &sackEnabled); err != nil {
		sackEnabled = false
	}

	synOpts := header.TCPSynOptions{
		WS:            h.rcvWndScale,
		TS:            true,
		TSVal:         h.ep.tsValNow(),
		TSEcr:         h.ep.recentTimestamp(),
		SACKPermitted: bool(sackEnabled),
		MSS:           h.ep.amss,
	}

	if h.state == handshakeSynRcvd {
		synOpts.TS = h.ep.SendTSOk
		synOpts.SACKPermitted = h.ep.SACKPermitted && bool(sackEnabled)
		if h.sndWndScale < 0 {
			synOpts.WS = -1
		}
	}

	h.sendSYNOpts = synOpts
	h.ep.sendSynTCP(h.ep.route, tcpFields{
		id:        h.ep.TransportEndpointInfo.ID,
		ttl:       calculateTTL(h.ep.route, h.ep.ipv4TTL, h.ep.ipv6HopLimit),
		tos:       h.ep.sendTOS,
		flags:     h.flags,
		seq:       h.iss,
		ack:       h.ackNum,
		rcvWnd:    h.rcvWnd,
		df:        h.ep.pmtud == tcpip.PMTUDiscoveryWant || h.ep.pmtud == tcpip.PMTUDiscoveryDo || h.ep.pmtud == tcpip.PMTUDiscoveryProbe,
		expOptVal: h.ep.getExperimentOptionValue(h.ep.route),
	}, synOpts)
}

func (h *handshake) retransmitHandlerLocked() tcpip.Error {
	e := h.ep
	if !e.EndpointState().connecting() {
		return nil
	}

	if err := h.retransmitTimer.reset(); err != nil {
		return err
	}

	if h.active || !h.acked || h.deferAccept != 0 && e.stack.Clock().NowMonotonic().Sub(h.startTime) > h.deferAccept {
		e.sendSynTCP(e.route, tcpFields{
			id:        e.TransportEndpointInfo.ID,
			ttl:       calculateTTL(e.route, e.ipv4TTL, e.ipv6HopLimit),
			tos:       e.sendTOS,
			flags:     h.flags,
			seq:       h.iss,
			ack:       h.ackNum,
			rcvWnd:    h.rcvWnd,
			df:        h.ep.pmtud == tcpip.PMTUDiscoveryWant || h.ep.pmtud == tcpip.PMTUDiscoveryDo || h.ep.pmtud == tcpip.PMTUDiscoveryProbe,
			expOptVal: e.getExperimentOptionValue(e.route),
		}, h.sendSYNOpts)
		h.sampleRTTWithTSOnly = true
	}
	return nil
}

func (h *handshake) transitionToStateEstablishedLocked(s *segment) {
	if h.retransmitTimer != nil {
		h.retransmitTimer.stop()
	}

	initSender(h.ep, h.iss, h.ackNum-1, h.sndWnd, h.mss, h.sndWndScale)

	rcvd := s.rcvdTime

	var rtt time.Duration
	if h.ep.SendTSOk && s.parsedOptions.TSEcr != 0 {
		rtt = h.ep.elapsed(rcvd, s.parsedOptions.TSEcr)
	}
	if !h.sampleRTTWithTSOnly && rtt == 0 {
		rtt = rcvd.Sub(h.startTime)
	}

	if rtt > 0 {
		h.ep.snd.updateRTO(rtt)
	}

	h.ep.rcvQueueMu.Lock()
	h.ep.rcv = newReceiver(h.ep, h.ackNum-1, h.rcvWnd, h.effectiveRcvWndScale())
	h.ep.RcvAutoParams.PrevCopiedBytes = int(h.rcvWnd)
	h.ep.rcvQueueMu.Unlock()

	h.ep.setEndpointState(StateEstablished)

	h.ep.route.ConfirmReachable()

	h.ep.waiterQueue.Notify(waiter.WritableEvents)
}

type backoffTimer struct {
	timeout    time.Duration
	maxTimeout time.Duration
	t          tcpip.Timer
}

func newBackoffTimer(clock tcpip.Clock, timeout, maxTimeout time.Duration, f func()) (*backoffTimer, tcpip.Error) {
	if timeout > maxTimeout {
		return nil, &tcpip.ErrTimeout{}
	}
	bt := &backoffTimer{timeout: timeout, maxTimeout: maxTimeout}
	bt.t = clock.AfterFunc(timeout, f)
	return bt, nil
}

func (bt *backoffTimer) reset() tcpip.Error {
	bt.timeout *= 2
	if bt.timeout > bt.maxTimeout {
		return &tcpip.ErrTimeout{}
	}
	bt.t.Reset(bt.timeout)
	return nil
}

func (bt *backoffTimer) reinit(timeout time.Duration) {
	bt.timeout = timeout
	bt.t.Reset(bt.timeout)
}

func (bt *backoffTimer) stop() {
	bt.t.Stop()
}

func parseSynSegmentOptions(s *segment) header.TCPSynOptions {
	synOpts := header.ParseSynOptions(s.options, s.flags.Contains(header.TCPFlagAck))
	if synOpts.TS {
		s.parsedOptions.TSVal = synOpts.TSVal
		s.parsedOptions.TSEcr = synOpts.TSEcr
	}
	return synOpts
}

var optionPool = sync.Pool{
	New: func() any {
		return &[maxOptionSize]byte{}
	},
}

func getOptions() []byte {
	return (*optionPool.Get().(*[maxOptionSize]byte))[:]
}

func putOptions(options []byte) {
	optionPool.Put(optionsToArray(options))
}

func makeSynOptions(opts header.TCPSynOptions) []byte {
	options := getOptions()

	offset := header.EncodeMSSOption(uint32(opts.MSS), options)

	if opts.TS && opts.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.TS {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.SACKPermitted {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKPermittedOption(options[offset:])
	}

	if opts.WS >= 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeWSOption(opts.WS, options[offset:])
	}

	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

type tcpFields struct {
	id        stack.TransportEndpointID
	ttl       uint8
	tos       uint8
	flags     header.TCPFlags
	seq       seqnum.Value
	ack       seqnum.Value
	rcvWnd    seqnum.Size
	opts      []byte
	txHash    uint32
	df        bool
	expOptVal uint16
}

func (e *Endpoint) sendSynTCP(r *stack.Route, tf tcpFields, opts header.TCPSynOptions) tcpip.Error {
	tf.opts = makeSynOptions(opts)
	hdrSize := header.TCPMinimumSize + int(r.MaxHeaderLength()) + len(tf.opts)
	if r.NetProto() == header.IPv6ProtocolNumber && tf.expOptVal != 0 {
		hdrSize += header.IPv6ExperimentHdrLength
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: hdrSize,
		Mark:               e.ops.GetMark(),
	})
	defer p.DecRef()
	if err := e.sendTCP(r, tf, p, stack.GSO{}); err != nil {
		e.stats.SendErrors.SynSendToNetworkFailed.Increment()
	}
	putOptions(tf.opts)
	return nil
}

func (e *Endpoint) sendTCP(r *stack.Route, tf tcpFields, pkt *stack.PacketBuffer, gso stack.GSO) tcpip.Error {
	tf.txHash = e.txHash
	if err := sendTCP(r, tf, pkt, gso, e.owner); err != nil {
		e.stats.SendErrors.SegmentSendToNetworkFailed.Increment()
		return err
	}
	e.stats.SegmentsSent.Increment()
	return nil
}

func buildTCPHdr(r *stack.Route, tf tcpFields, pkt *stack.PacketBuffer, gso stack.GSO) {
	optLen := len(tf.opts)
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize + optLen))
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	tcp.Encode(&header.TCPFields{
		SrcPort:    tf.id.LocalPort,
		DstPort:    tf.id.RemotePort,
		SeqNum:     uint32(tf.seq),
		AckNum:     uint32(tf.ack),
		DataOffset: uint8(header.TCPMinimumSize + optLen),
		Flags:      tf.flags,
		WindowSize: uint16(tf.rcvWnd),
	})
	copy(tcp[header.TCPMinimumSize:], tf.opts)

	xsum := r.PseudoHeaderChecksum(ProtocolNumber, uint16(pkt.Size()))
	if gso.Type != stack.GSONone && gso.NeedsCsum {
		tcp.SetChecksum(xsum)
	} else if r.RequiresTXTransportChecksum() {
		xsum = checksum.Combine(xsum, pkt.Data().Checksum())
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	}
}

func sendTCPBatch(r *stack.Route, tf tcpFields, pkt *stack.PacketBuffer, gso stack.GSO, owner tcpip.PacketOwner) tcpip.Error {
	optLen := len(tf.opts)
	if tf.rcvWnd > math.MaxUint16 {
		tf.rcvWnd = math.MaxUint16
	}

	mss := int(gso.MSS)
	n := (pkt.Data().Size() + mss - 1) / mss

	size := pkt.Data().Size()
	hdrSize := header.TCPMinimumSize + int(r.MaxHeaderLength()) + optLen
	for i := 0; i < n; i++ {
		packetSize := mss
		if packetSize > size {
			packetSize = size
		}
		size -= packetSize

		pkt := pkt
		shouldSplitPacket := i != n-1
		if shouldSplitPacket {
			if r.NetProto() == header.IPv6ProtocolNumber && tf.expOptVal != 0 {
				hdrSize += header.IPv6ExperimentHdrLength
			}
			splitPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: hdrSize,
				Mark:               pkt.Mark,
			})
			splitPkt.Data().ReadFromPacketData(pkt.Data(), packetSize)
			pkt = splitPkt
		}
		pkt.Hash = tf.txHash
		pkt.Owner = owner

		buildTCPHdr(r, tf, pkt, gso)
		tf.seq = tf.seq.Add(seqnum.Size(packetSize))
		pkt.GSOOptions = gso
		if err := r.WritePacket(stack.NetworkHeaderParams{
			Protocol:              ProtocolNumber,
			TTL:                   tf.ttl,
			TOS:                   tf.tos,
			DF:                    tf.df,
			ExperimentOptionValue: tf.expOptVal,
		}, pkt); err != nil {
			r.Stats().TCP.SegmentSendErrors.Increment()
			if shouldSplitPacket {
				pkt.DecRef()
			}
			return err
		}
		r.Stats().TCP.SegmentsSent.Increment()
		if shouldSplitPacket {
			pkt.DecRef()
		}
	}
	return nil
}

func sendTCP(r *stack.Route, tf tcpFields, pkt *stack.PacketBuffer, gso stack.GSO, owner tcpip.PacketOwner) tcpip.Error {
	if tf.rcvWnd > math.MaxUint16 {
		tf.rcvWnd = math.MaxUint16
	}

	if r.Loop()&stack.PacketLoop == 0 && gso.Type == stack.GSOGvisor && int(gso.MSS) < pkt.Data().Size() {
		return sendTCPBatch(r, tf, pkt, gso, owner)
	}

	pkt.GSOOptions = gso
	pkt.Hash = tf.txHash
	pkt.Owner = owner
	buildTCPHdr(r, tf, pkt, gso)

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol:              ProtocolNumber,
		TTL:                   tf.ttl,
		TOS:                   tf.tos,
		DF:                    tf.df,
		ExperimentOptionValue: tf.expOptVal,
	}, pkt); err != nil {
		r.Stats().TCP.SegmentSendErrors.Increment()
		return err
	}
	r.Stats().TCP.SegmentsSent.Increment()
	if (tf.flags & header.TCPFlagRst) != 0 {
		r.Stats().TCP.ResetsSent.Increment()
	}
	return nil
}

func (e *Endpoint) makeOptions(sackBlocks []header.SACKBlock) []byte {
	options := getOptions()
	offset := 0

	if e.SendTSOk {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(e.tsValNow(), e.recentTimestamp(), options[offset:])
	}
	if e.SACKPermitted && len(sackBlocks) > 0 {
		budget := len(options)
		if e.route != nil {
			if available := int(e.route.MTU()) - header.TCPMinimumSize - 1; available < budget {
				budget = available
			}
		}
		blocks := (budget - offset - 4) / 8
		if blocks > len(sackBlocks) {
			blocks = len(sackBlocks)
		}
		if blocks > 0 {
			offset += header.EncodeNOP(options[offset:])
			offset += header.EncodeNOP(options[offset:])
			offset += header.EncodeSACKBlocks(sackBlocks[:blocks], options[offset:])
		}
	}

	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

func (e *Endpoint) sendEmptyRaw(flags header.TCPFlags, seq, ack seqnum.Value, rcvWnd seqnum.Size) tcpip.Error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Mark: e.ops.GetMark(),
	})
	defer pkt.DecRef()
	return e.sendRaw(pkt, flags, seq, ack, rcvWnd)
}

func (e *Endpoint) sendRaw(pkt *stack.PacketBuffer, flags header.TCPFlags, seq, ack seqnum.Value, rcvWnd seqnum.Size) tcpip.Error {
	var sackBlocks []header.SACKBlock
	if e.EndpointState() == StateEstablished && e.rcv.pendingRcvdSegments.Len() > 0 && (flags&header.TCPFlagAck != 0) {
		sackBlocks = e.sack.Blocks[:e.sack.NumBlocks]
	}
	options := e.makeOptions(sackBlocks)
	defer putOptions(options)
	hdrSize := header.TCPMinimumSize + int(e.route.MaxHeaderLength()) + len(options)
	expOptVal := e.getExperimentOptionValue(e.route)
	if e.route.NetProto() == header.IPv6ProtocolNumber && expOptVal != 0 {
		hdrSize += header.IPv6ExperimentHdrLength
	}
	pkt.ReserveHeaderBytes(hdrSize)
	return e.sendTCP(e.route, tcpFields{
		id:     e.TransportEndpointInfo.ID,
		ttl:    calculateTTL(e.route, e.ipv4TTL, e.ipv6HopLimit),
		tos:    e.sendTOS,
		flags:  flags,
		seq:    seq,
		ack:    ack,
		rcvWnd: rcvWnd,
		opts:   options,
		df:        e.pmtud == tcpip.PMTUDiscoveryWant || e.pmtud == tcpip.PMTUDiscoveryDo || e.pmtud == tcpip.PMTUDiscoveryProbe,
		expOptVal: expOptVal,
	}, pkt, e.gso)
}

func (e *Endpoint) sendData(next *segment) {
	if e.snd.writeNext == nil {
		if next == nil {
			return
		}
		e.snd.updateWriteNext(next)
	}

	e.snd.sendData()
}

func (e *Endpoint) resetConnectionLocked(err tcpip.Error) {
	e.hardError = err
	switch err.(type) {
	case *tcpip.ErrConnectionReset, *tcpip.ErrTimeout:
	default:
		var resetSeqNum seqnum.Value
		var ackNum seqnum.Value
		if e.snd != nil {
			sndWndEnd := e.snd.SndUna.Add(e.snd.SndWnd)
			resetSeqNum = sndWndEnd
			if !sndWndEnd.LessThan(e.snd.SndNxt) || e.snd.SndNxt.Size(sndWndEnd) < (1<<e.snd.SndWndScale) {
				resetSeqNum = e.snd.SndNxt
			}
		}
		if e.rcv != nil {
			ackNum = e.rcv.RcvNxt
		}
		e.sendEmptyRaw(header.TCPFlagAck|header.TCPFlagRst, resetSeqNum, ackNum, 0)
	}
	e.purgeWriteQueue()
	e.purgePendingRcvQueue()
	e.cleanupLocked()
	e.setEndpointState(StateError)
}

func (e *Endpoint) transitionToStateCloseLocked() {
	s := e.EndpointState()
	if s == StateClose {
		return
	}

	if s.connected() {
		e.stack.Stats().TCP.EstablishedClosed.Increment()
	}

	e.cleanupLocked()
	e.setEndpointState(StateClose)
}

func (e *Endpoint) tryDeliverSegmentFromClosedEndpoint(s *segment) {
	ep := e.stack.FindTransportEndpoint(e.NetProto, e.TransProto, e.TransportEndpointInfo.ID, s.pkt.NICID)
	if ep == nil && e.NetProto == header.IPv6ProtocolNumber && e.TransportEndpointInfo.ID.LocalAddress.To4() != (tcpip.Address{}) {
		ep = e.stack.FindTransportEndpoint(
			header.IPv4ProtocolNumber,
			e.TransProto,
			e.TransportEndpointInfo.ID,
			s.pkt.NICID,
		)
	}
	if ep == nil {
		if !s.flags.Contains(header.TCPFlagRst) {
			replyWithReset(e.stack, s, stack.DefaultTOS, tcpip.UseDefaultIPv4TTL, tcpip.UseDefaultIPv6HopLimit)
		}
		return
	}

	if e == ep {
		panic(fmt.Sprintf("current endpoint not removed from demuxer, enqueuing segments to itself, endpoint in state %v", e.EndpointState()))
	}

	if ep := ep.(*Endpoint); ep.enqueueSegment(s) {
		ep.notifyProcessor()
	}
}

func (e *Endpoint) drainClosingSegmentQueue() {
	for {
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}

		e.tryDeliverSegmentFromClosedEndpoint(s)
		s.DecRef()
	}
}

func (e *Endpoint) handleReset(s *segment) (ok bool, err tcpip.Error) {
	if !e.rcv.acceptable(s.sequenceNumber, 0) {
		return true, nil
	}

	if s.sequenceNumber != e.rcv.RcvNxt {
		e.snd.maybeSendOutOfWindowAck(s)
		return true, nil
	}

	switch e.EndpointState() {
	case StateCloseWait:
		e.transitionToStateCloseLocked()
		e.hardError = &tcpip.ErrAborted{}
		return false, nil
	default:
		return false, &tcpip.ErrConnectionReset{}
	}
}

func (e *Endpoint) handleSegmentsLocked() tcpip.Error {
	sndUna := e.snd.SndUna
	for i := 0; i < maxSegmentsPerWake; i++ {
		if state := e.EndpointState(); state.closed() || state == StateTimeWait || state == StateError {
			return nil
		}
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}
		cont, err := e.handleSegmentLocked(s)
		s.DecRef()
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}

	if sndUna.LessThan(e.snd.SndUna) {
		e.route.ConfirmReachable()
	}

	if e.rcv.RcvNxt != e.snd.MaxSentAck {
		e.snd.sendAck()
	}

	e.resetKeepaliveTimer(true)

	return nil
}

func (e *Endpoint) probeSegmentLocked() {
	if fn := e.probe; fn != nil {
		var state TCPEndpointState
		e.completeStateLocked(&state)
		fn(&state)
	}
}

func (e *Endpoint) handleSegmentLocked(s *segment) (cont bool, err tcpip.Error) {
	defer e.probeSegmentLocked()

	if s.flags.Contains(header.TCPFlagRst) {
		if ok, err := e.handleReset(s); !ok {
			return false, err
		}
	} else if s.flags.Contains(header.TCPFlagSyn) {

		e.snd.maybeSendOutOfWindowAck(s)
	} else if s.flags.Contains(header.TCPFlagAck) {
		s.window <<= e.snd.SndWndScale

		drop, err := e.rcv.handleRcvdSegment(s)
		if err != nil {
			return false, err
		}
		if drop {
			return true, nil
		}

		state := e.EndpointState()
		if state == StateClose || state == StateError {
			return false, nil
		}

		e.snd.handleRcvdSegment(s)
	}

	return true, nil
}

func (e *Endpoint) keepaliveTimerExpired() tcpip.Error {
	userTimeout := e.userTimeout

	if e.route == nil {
		return nil
	}
	e.keepalive.Lock()
	if !e.SocketOptions().GetKeepAlive() || e.keepalive.timer.isUninitialized() || !e.keepalive.timer.checkExpiration() {
		e.keepalive.Unlock()
		return nil
	}

	if userTimeout != 0 && e.stack.Clock().NowMonotonic().Sub(e.rcv.lastRcvdAckTime) >= userTimeout && e.keepalive.unacked > 0 {
		e.keepalive.Unlock()
		e.stack.Stats().TCP.EstablishedTimedout.Increment()
		return &tcpip.ErrTimeout{}
	}

	if e.keepalive.unacked >= e.keepalive.count {
		e.keepalive.Unlock()
		e.stack.Stats().TCP.EstablishedTimedout.Increment()
		return &tcpip.ErrTimeout{}
	}

	e.keepalive.unacked++
	e.keepalive.Unlock()
	e.snd.sendEmptySegment(header.TCPFlagAck, e.snd.SndNxt-1)
	e.resetKeepaliveTimer(false)
	return nil
}

func (e *Endpoint) resetKeepaliveTimer(receivedData bool) {
	e.keepalive.Lock()
	defer e.keepalive.Unlock()
	if e.keepalive.timer.isUninitialized() {
		if state := e.EndpointState(); !state.closed() {
			panic(fmt.Sprintf("Unexpected state when the keepalive time is cleaned up, got %s, want %s or %s", state, StateClose, StateError))
		}
		return
	}
	if receivedData {
		e.keepalive.unacked = 0
	}
	if !e.SocketOptions().GetKeepAlive() || e.snd == nil || e.snd.SndUna != e.snd.SndNxt {
		e.keepalive.timer.disable()
		return
	}
	if e.keepalive.unacked > 0 {
		e.keepalive.timer.enable(e.keepalive.interval)
	} else {
		e.keepalive.timer.enable(e.keepalive.idle)
	}
}

func (e *Endpoint) disableKeepaliveTimer() {
	e.keepalive.Lock()
	e.keepalive.timer.disable()
	e.keepalive.Unlock()
}

func (e *Endpoint) finWait2TimerExpired() {
	e.mu.Lock()
	e.transitionToStateCloseLocked()
	e.mu.Unlock()
	e.drainClosingSegmentQueue()
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (e *Endpoint) handshakeFailed(err tcpip.Error) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
	if e.h != nil && e.h.retransmitTimer != nil {
		e.h.retransmitTimer.stop()
	}
	e.hardError = err
	e.cleanupLocked()
	e.setEndpointState(StateError)
}

func (e *Endpoint) handleTimeWaitSegments() (extendTimeWait bool, reuseTW func()) {
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}
		extTW, newSyn := e.rcv.handleTimeWaitSegment(s)
		if newSyn {
			info := e.TransportEndpointInfo
			newID := info.ID
			newID.RemoteAddress = tcpip.Address{}
			newID.RemotePort = 0
			netProtos := []tcpip.NetworkProtocolNumber{info.NetProto}
			if newID.LocalAddress.To4() != (tcpip.Address{}) {
				netProtos = []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber}
			}
			for _, netProto := range netProtos {
				if listenEP := e.stack.FindTransportEndpoint(netProto, info.TransProto, newID, s.pkt.NICID); listenEP != nil {
					tcpEP := listenEP.(*Endpoint)
					if EndpointState(tcpEP.State()) == StateListen {
						reuseTW = func() {
							if !tcpEP.enqueueSegment(s) {
								return
							}
							tcpEP.notifyProcessor()
							s.DecRef()
						}
						return false, reuseTW
					}
				}
			}
		}
		if extTW {
			extendTimeWait = true
		}
		s.DecRef()
	}
	return extendTimeWait, nil
}

func (e *Endpoint) getTimeWaitDuration() time.Duration {
	timeWaitDuration := DefaultTCPTimeWaitTimeout

	var tcpTW tcpip.TCPTimeWaitTimeoutOption
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &tcpTW); err == nil {
		timeWaitDuration = time.Duration(tcpTW)
	}
	return timeWaitDuration
}

func (e *Endpoint) timeWaitTimerExpired() {
	e.mu.Lock()
	if e.EndpointState() != StateTimeWait {
		e.mu.Unlock()
		return
	}
	e.transitionToStateCloseLocked()
	e.mu.Unlock()
	e.drainClosingSegmentQueue()
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

func (e *Endpoint) notifyProcessor() {
	if !e.mu.TryLock() {
		return
	}
	processor := e.protocol.dispatcher.selectProcessor(e.ID)
	e.mu.Unlock()
	processor.queueEndpoint(e)
}
