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
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/mathext"
	"github.com/enfein/mieru/v3/pkg/protocol/serveruser"
	"github.com/enfein/mieru/v3/pkg/stderror"
	"github.com/google/btree"
)

const (
	maxPDU = 32 * 1024

	txCountLimit = 20

	segmentTimeFormat = "15:04:05.999"
)

func maxFragmentSize(mtu int, transport common.TransportProtocol, mode appctlpb.LowEntropyMode) (int, error) {
	if mode == appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF {
		return maxFragmentSizeInternal(mtu, transport), nil
	}

	params, err := buildLowEntropyParams(mode)
	if err != nil {
		return 0, err
	}
	maxEncodableChunkCount := math.MaxUint16 / lowEntropyChunkLen

	switch transport {
	case common.StreamTransport:
		fragmentSize := maxFragmentSizeInternal(mtu, transport)
		maxEncodableFragmentSize := maxEncodableChunkCount * params.sourceBytesPerChunk
		return mathext.Min(fragmentSize, maxEncodableFragmentSize), nil
	case common.PacketTransport:
		mtuChunkCount := (mtu - packetOverhead) / lowEntropyChunkLen
		if mtuChunkCount <= 0 {
			return 0, fmt.Errorf("MTU %d has no capacity for a low entropy payload chunk", mtu)
		}
		return mtuChunkCount * params.sourceBytesPerChunk, nil
	default:
		return maxFragmentSizeInternal(mtu, transport), nil
	}
}

func maxFragmentSizeInternal(mtu int, transport common.TransportProtocol) int {
	if transport == common.StreamTransport {
		return maxPDU
	}

	res := mtu - packetOverhead
	return mathext.Max(0, res)
}

type segment struct {
	metadata  metadata
	payload   []byte
	transport common.TransportProtocol
	ackCount  byte
	txCount   byte
	txTime    int64
	txTimeout time.Duration
	block     cipher.BlockCipher

	serverUserPolicy serveruser.Policy

	serverUserAuthentication serveruser.Authentication
}

func (s *segment) Protocol() protocolType {
	return s.metadata.Protocol()
}

func (s *segment) SessionID() (uint32, error) {
	das, ok := s.metadata.(*dataAckStruct)
	if ok {
		return das.sessionID, nil
	}
	ss, ok := s.metadata.(*sessionStruct)
	if ok {
		return ss.sessionID, nil
	}
	return 0, stderror.ErrUnsupported
}

func (s *segment) Seq() (uint32, error) {
	das, ok := s.metadata.(*dataAckStruct)
	if ok {
		return das.seq, nil
	}
	ss, ok := s.metadata.(*sessionStruct)
	if ok {
		return ss.seq, nil
	}
	return 0, stderror.ErrUnsupported
}

func (s *segment) Fragment() uint8 {
	das, ok := s.metadata.(*dataAckStruct)
	if !ok {
		return 0
	}
	return das.fragment
}

func (s *segment) Less(other *segment) bool {
	mySeq, err := s.Seq()
	if err != nil {
		panic(fmt.Sprintf("%v Seq() failed: %v", s, err))
	}
	otherSeq, err := other.Seq()
	if err != nil {
		panic(fmt.Sprintf("%v Seq() failed: %v", other, err))
	}
	return mySeq < otherSeq
}

func (s *segment) String() string {
	if s.transport == common.PacketTransport && (s.txTime != 0 || s.txTimeout != 0) {
		return fmt.Sprintf("segment{metadata=%v, realPayloadLen=%v, ackCount=%v, txCount=%v, txTime=%v, txTimeout=%v}", s.metadata, len(s.payload), s.ackCount, s.txCount, time.UnixMicro(s.txTime).Format(segmentTimeFormat), s.txTimeout)
	}
	return fmt.Sprintf("segment{metadata=%v, realPayloadLen=%v}", s.metadata, len(s.payload))
}

func segmentLessFunc(a, b *segment) bool {
	return a.Less(b)
}

type segmentIterator func(*segment) bool

type segmentTree struct {
	tr  *btree.BTreeG[*segment]
	cap int

	mu                sync.Mutex
	chanEmptyEvent    chan struct{}
	chanNotEmptyEvent chan struct{}
}

func newSegmentTree(capacity int) *segmentTree {
	if capacity <= 0 {
		panic("segment tree capacity is <= 0")
	}
	st := &segmentTree{
		tr:  btree.NewG(4, segmentLessFunc),
		cap: capacity,
	}
	st.chanEmptyEvent = make(chan struct{}, 1)
	st.chanNotEmptyEvent = make(chan struct{}, 1)
	return st
}

func (t *segmentTree) Insert(seg *segment) (ok bool) {
	t.checkNil(seg)
	t.checkSeq(seg)
	t.checkProtocolType(seg)
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tr.Len() >= t.cap {
		t.notifyNotEmpty()
		return false
	}
	prev, replace := t.tr.ReplaceOrInsert(seg)
	if replace {
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v is replaced by %v", prev, seg)
		}
	} else {
		t.notifyNotEmpty()
	}
	return true
}

func (t *segmentTree) DeleteMin() (*segment, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tr.Len() == 0 {
		return nil, false
	}
	seg, ok := t.tr.DeleteMin()
	if !ok {
		panic("segmentTree.DeleteMin() is called when the tree is empty")
	}
	if seg == nil {
		panic("segmentTree.DeleteMin() return nil")
	}
	if t.tr.Len() > 0 {
		t.notifyNotEmpty()
	} else {
		t.notifyEmpty()
	}
	return seg, true
}

func (t *segmentTree) DeleteMinIf(si segmentIterator) (*segment, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tr.Len() == 0 {
		return nil, false
	}
	seg, ok := t.tr.Min()
	if !ok {
		panic("segmentTree.Min() is called when the tree is empty")
	}
	if seg == nil {
		panic("segmentTree.Min() return nil")
	}
	shouldDelete := si(seg)
	if shouldDelete {
		seg, ok = t.tr.DeleteMin()
		if !ok {
			panic("segmentTree.DeleteMin() is called when the tree is empty")
		}
		if seg == nil {
			panic("segmentTree.DeleteMin() return nil")
		}
	}
	if t.tr.Len() > 0 {
		t.notifyNotEmpty()
	} else {
		t.notifyEmpty()
	}
	return seg, shouldDelete
}

func (t *segmentTree) DeleteAll() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.tr.Clear(false)
	t.notifyEmpty()
}

func (t *segmentTree) Ascend(si segmentIterator) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tr.Len() == 0 {
		return
	}
	t.tr.Ascend(btree.ItemIteratorG[*segment](si))
}

func (t *segmentTree) MinSeq() (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	seg, ok := t.tr.Min()
	if !ok {
		return 0, stderror.ErrEmpty
	}
	return seg.Seq()
}

func (t *segmentTree) MaxSeq() (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	seg, ok := t.tr.Max()
	if !ok {
		return 0, stderror.ErrEmpty
	}
	return seg.Seq()
}

func (t *segmentTree) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tr.Len()
}

func (t *segmentTree) Remaining() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cap - t.tr.Len()
}

func (t *segmentTree) notifyEmpty() {
	select {
	case t.chanEmptyEvent <- struct{}{}:
	default:
	}
}

func (t *segmentTree) notifyNotEmpty() {
	select {
	case t.chanNotEmptyEvent <- struct{}{}:
	default:
	}
}

func (t *segmentTree) checkNil(seg *segment) {
	if seg == nil {
		panic("Inserting nil segment to the segment tree")
	}
}

func (t *segmentTree) checkSeq(seg *segment) {
	if _, err := seg.Seq(); err != nil {
		panic(fmt.Sprintf("Failed to get sequence number from %v: %v", seg, err))
	}
}

func (t *segmentTree) checkProtocolType(seg *segment) {
	protocol := seg.metadata.Protocol()
	if isSessionProtocol(protocol) || isDataProtocol(protocol) {
		return
	}
	panic(fmt.Sprintf("Inserting segment with unsupported type %v to the segment tree", protocol))
}
