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

package tcpconntrack

import (
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
)

type Result int

const (
	ResultDrop Result = iota

	ResultConnecting

	ResultAlive

	ResultReset

	ResultClosedByResponder

	ResultClosedByOriginator
)

const maxWindowShift = 14

type TCB struct {
	reply    stream
	original stream

	handlerReply    func(tcb *TCB, hdr header.TCP, dataLen int) Result `state:"nosave"`
	handlerOriginal func(tcb *TCB, hdr header.TCP, dataLen int) Result `state:"nosave"`

	firstFin *stream

	state Result
}

func (t *TCB) Init(initialSyn header.TCP, dataLen int) Result {
	t.handlerReply = synSentStateReply
	t.handlerOriginal = synSentStateOriginal

	iss := seqnum.Value(initialSyn.SequenceNumber())
	t.original.una = iss
	t.original.nxt = iss.Add(logicalLenSyn(initialSyn, dataLen))
	t.original.end = t.original.nxt
	t.reply.shiftCnt = header.ParseSynOptions(initialSyn.Options(), false).WS

	t.reply.una = 0
	t.reply.nxt = 0
	t.reply.end = seqnum.Value(initialSyn.WindowSize())
	t.state = ResultConnecting
	return t.state
}

func (t *TCB) UpdateStateReply(tcp header.TCP, dataLen int) Result {
	st := t.handlerReply(t, tcp, dataLen)
	if st != ResultDrop {
		t.state = st
	}
	return st
}

func (t *TCB) UpdateStateOriginal(tcp header.TCP, dataLen int) Result {
	st := t.handlerOriginal(t, tcp, dataLen)
	if st != ResultDrop {
		t.state = st
	}
	return st
}

func (t *TCB) State() Result {
	return t.state
}

func (t *TCB) IsAlive() bool {
	return !t.reply.rstSeen && !t.original.rstSeen && (!t.reply.closed() || !t.original.closed())
}

func (t *TCB) OriginalSendSequenceNumber() seqnum.Value {
	return t.original.nxt
}

func (t *TCB) ReplySendSequenceNumber() seqnum.Value {
	return t.reply.nxt
}

func (t *TCB) adaptResult(r Result) Result {
	if r != ResultAlive || !t.reply.closed() || !t.original.closed() {
		return r
	}

	if t.firstFin == &t.original {
		return ResultClosedByOriginator
	}

	return ResultClosedByResponder
}

func synSentStateReply(t *TCB, tcp header.TCP, dataLen int) Result {
	flags := tcp.Flags()
	ackPresent := flags&header.TCPFlagAck != 0
	ack := seqnum.Value(tcp.AckNumber())

	if ackPresent && !(ack-1).InRange(t.original.una, t.original.nxt) {
		return ResultConnecting
	}

	if flags&header.TCPFlagRst != 0 {
		if ackPresent {
			t.reply.rstSeen = true
			return ResultReset
		}
		return ResultConnecting
	}

	if flags&header.TCPFlagSyn == 0 {
		return ResultConnecting
	}

	t.original.shiftCnt = header.ParseSynOptions(tcp.Options(), ackPresent).WS

	if t.original.shiftCnt != -1 && t.reply.shiftCnt != -1 {
		if t.original.shiftCnt > maxWindowShift {
			t.original.shiftCnt = maxWindowShift
		}
		if t.reply.shiftCnt > maxWindowShift {
			t.original.shiftCnt = maxWindowShift
		}
	} else {
		t.original.shiftCnt = 0
		t.reply.shiftCnt = 0
	}
	irs := seqnum.Value(tcp.SequenceNumber())
	t.reply.una = irs
	t.reply.nxt = irs.Add(logicalLen(tcp, dataLen, seqnum.Size(t.reply.end)))
	t.reply.end <<= t.reply.shiftCnt
	t.reply.end.UpdateForward(seqnum.Size(irs))

	windowSize := t.original.windowSize(tcp)
	t.original.end = t.original.una.Add(windowSize)

	if ackPresent {
		if t.original.una.LessThan(ack) {
			t.original.una = ack
		}

		if end := ack.Add(seqnum.Size(windowSize)); t.original.end.LessThan(end) {
			t.original.end = end
		}
	}

	t.handlerReply = allOtherReply
	t.handlerOriginal = allOtherOriginal

	return ResultAlive
}

func synSentStateOriginal(t *TCB, tcp header.TCP, _ int) Result {
	if tcp.Flags() != header.TCPFlagSyn || tcp.SequenceNumber() != uint32(t.original.una) {
		return ResultDrop
	}

	if wnd := seqnum.Value(tcp.WindowSize()); wnd > t.reply.end {
		t.reply.end = wnd
	}

	return ResultConnecting
}

func update(tcp header.TCP, reply, original *stream, firstFin **stream, dataLen int) Result {
	s := seqnum.Value(tcp.SequenceNumber())
	if !reply.acceptable(s, seqnum.Size(dataLen)) {
		return ResultAlive
	}

	flags := tcp.Flags()
	if flags&header.TCPFlagRst != 0 {
		reply.rstSeen = true
		return ResultReset
	}

	if flags&header.TCPFlagAck == 0 || flags&header.TCPFlagSyn != 0 {
		return ResultAlive
	}

	ack := seqnum.Value(tcp.AckNumber())
	if original.nxt.LessThan(ack) {
		return ResultAlive
	}

	if original.una.LessThan(ack) {
		original.una = ack
	}

	if end := ack.Add(original.windowSize(tcp)); original.end.LessThan(end) {
		original.end = end
	}

	end := s.Add(logicalLen(tcp, dataLen, reply.rwndSize()))
	if reply.nxt.LessThan(end) {
		reply.nxt = end
	}

	if flags&header.TCPFlagFin != 0 && !reply.finSeen {
		reply.finSeen = true
		reply.fin = end - 1

		if *firstFin == nil {
			*firstFin = reply
		}
	}

	return ResultAlive
}

func allOtherReply(t *TCB, tcp header.TCP, dataLen int) Result {
	return t.adaptResult(update(tcp, &t.reply, &t.original, &t.firstFin, dataLen))
}

func allOtherOriginal(t *TCB, tcp header.TCP, dataLen int) Result {
	return t.adaptResult(update(tcp, &t.original, &t.reply, &t.firstFin, dataLen))
}

type stream struct {
	una seqnum.Value
	nxt seqnum.Value
	end seqnum.Value

	finSeen bool

	fin seqnum.Value

	rstSeen bool

	shiftCnt int
}

func (s *stream) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	return header.Acceptable(segSeq, segLen, s.una, s.end)
}

func (s *stream) closed() bool {
	return s.finSeen && s.fin.LessThan(s.una)
}

func (s *stream) rwndSize() seqnum.Size {
	return s.una.Size(s.end)
}

func (s *stream) windowSize(tcp header.TCP) seqnum.Size {
	return seqnum.Size(tcp.WindowSize()) << s.shiftCnt
}

func logicalLenSyn(tcp header.TCP, dataLen int) seqnum.Size {
	length := seqnum.Size(dataLen)
	flags := tcp.Flags()
	if flags&header.TCPFlagSyn != 0 {
		length++
	}
	if flags&header.TCPFlagFin != 0 {
		length++
	}
	return length
}

func logicalLen(tcp header.TCP, dataLen int, windowSize seqnum.Size) seqnum.Size {
	length := logicalLenSyn(tcp, dataLen)
	if length > windowSize {
		length = windowSize
	}
	return length
}

func (t *TCB) IsEmpty() bool {
	if t.reply != (stream{}) || t.original != (stream{}) {
		return false
	}

	if t.firstFin != nil || t.state != ResultDrop {
		return false
	}

	return true
}
