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

package fragmentation

import (
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	HighFragThreshold = 4 << 20

	LowFragThreshold = 3 << 20

	minBlockSize = 1
)

var (
	ErrInvalidArgs = errors.New("invalid args")

	ErrFragmentOverlap = errors.New("overlapping fragments")

	ErrFragmentConflict = errors.New("conflicting fragments")
)

type FragmentID struct {
	Source tcpip.Address

	Destination tcpip.Address

	ID uint32

	Protocol uint8
}

type Fragmentation struct {
	mu             sync.Mutex `state:"nosave"`
	highLimit      int
	lowLimit       int
	reassemblers   map[FragmentID]*reassembler
	rList          reassemblerList
	memSize        int
	timeout        time.Duration
	blockSize      uint16
	clock          tcpip.Clock
	releaseJob     *tcpip.Job
	timeoutHandler TimeoutHandler
}

type TimeoutHandler interface {
	OnReassemblyTimeout(pkt *stack.PacketBuffer)
}

func NewFragmentation(blockSize uint16, highMemoryLimit, lowMemoryLimit int, reassemblingTimeout time.Duration, clock tcpip.Clock, timeoutHandler TimeoutHandler) *Fragmentation {
	if lowMemoryLimit >= highMemoryLimit {
		lowMemoryLimit = highMemoryLimit
	}

	if lowMemoryLimit < 0 {
		lowMemoryLimit = 0
	}

	if blockSize < minBlockSize {
		blockSize = minBlockSize
	}

	f := &Fragmentation{
		reassemblers:   make(map[FragmentID]*reassembler),
		highLimit:      highMemoryLimit,
		lowLimit:       lowMemoryLimit,
		timeout:        reassemblingTimeout,
		blockSize:      blockSize,
		clock:          clock,
		timeoutHandler: timeoutHandler,
	}
	f.releaseJob = tcpip.NewJob(f.clock, &f.mu, f.releaseReassemblersLocked)

	return f
}

func (f *Fragmentation) Process(
	id FragmentID, first, last uint16, more bool, proto uint8, pkt *stack.PacketBuffer) (
	*stack.PacketBuffer, uint8, bool, error) {
	if first > last {
		return nil, 0, false, fmt.Errorf("first=%d is greater than last=%d: %w", first, last, ErrInvalidArgs)
	}

	if first%f.blockSize != 0 {
		return nil, 0, false, fmt.Errorf("first=%d is not a multiple of block size=%d: %w", first, f.blockSize, ErrInvalidArgs)
	}

	fragmentSize := last - first + 1
	if more && fragmentSize%f.blockSize != 0 {
		return nil, 0, false, fmt.Errorf("fragment size=%d bytes is not a multiple of block size=%d on non-final fragment: %w", fragmentSize, f.blockSize, ErrInvalidArgs)
	}

	if l := pkt.Data().Size(); l != int(fragmentSize) {
		return nil, 0, false, fmt.Errorf("got fragment size=%d bytes not equal to the expected fragment size=%d bytes (first=%d last=%d): %w", l, fragmentSize, first, last, ErrInvalidArgs)
	}

	f.mu.Lock()
	if f.reassemblers == nil {
		return nil, 0, false, fmt.Errorf("Release() called before fragmentation processing could finish")
	}

	r, ok := f.reassemblers[id]
	if !ok {
		r = newReassembler(id, f.clock)
		f.reassemblers[id] = r
		wasEmpty := f.rList.Empty()
		f.rList.PushFront(r)
		if wasEmpty {
			f.releaseReassemblersLocked()
		}
	}
	f.mu.Unlock()

	resPkt, firstFragmentProto, done, memConsumed, err := r.process(first, last, more, proto, pkt)
	if err != nil {
		f.mu.Lock()
		f.release(r, false)
		f.mu.Unlock()
		return nil, 0, false, fmt.Errorf("fragmentation processing error: %w", err)
	}
	f.mu.Lock()
	f.memSize += memConsumed
	if done {
		f.release(r, false)
	}
	if f.memSize > f.highLimit {
		for f.memSize > f.lowLimit {
			tail := f.rList.Back()
			if tail == nil {
				break
			}
			f.release(tail, false)
		}
	}
	f.mu.Unlock()
	return resPkt, firstFragmentProto, done, nil
}

func (f *Fragmentation) Release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.reassemblers {
		f.release(r, false)
	}
	f.reassemblers = nil
}

func (f *Fragmentation) release(r *reassembler, timedOut bool) {
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.memSize -= r.memSize
	if f.memSize < 0 {
		log.Warningf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.memSize)
		f.memSize = 0
	}

	if h := f.timeoutHandler; timedOut && h != nil {
		h.OnReassemblyTimeout(r.pkt)
	}
	if r.pkt != nil {
		r.pkt.DecRef()
		r.pkt = nil
	}
	for _, h := range r.holes {
		if h.pkt != nil {
			h.pkt.DecRef()
			h.pkt = nil
		}
	}
	r.holes = nil
}

func (f *Fragmentation) releaseReassemblersLocked() {
	now := f.clock.NowMonotonic()
	for {
		r := f.rList.Back()
		if r == nil {
			break
		}
		elapsed := now.Sub(r.createdAt)
		if f.timeout > elapsed {
			f.releaseJob.Schedule(f.timeout - elapsed)
			break
		}
		f.release(r, true)
	}
}

type PacketFragmenter struct {
	transportHeader    []byte
	data               buffer.Buffer
	reserve            int
	fragmentPayloadLen int
	fragmentCount      int
	currentFragment    int
	fragmentOffset     int
	mark               uint32
}

func MakePacketFragmenter(pkt *stack.PacketBuffer, fragmentPayloadLen uint32, reserve int) PacketFragmenter {
	var fragmentableData buffer.Buffer
	fragmentableData.Append(pkt.TransportHeader().View())
	pktBuf := pkt.Data().ToBuffer()
	fragmentableData.Merge(&pktBuf)
	fragmentCount := (uint32(fragmentableData.Size()) + fragmentPayloadLen - 1) / fragmentPayloadLen

	return PacketFragmenter{
		data:               fragmentableData,
		reserve:            reserve,
		fragmentPayloadLen: int(fragmentPayloadLen),
		fragmentCount:      int(fragmentCount),
		mark:               pkt.Mark,
	}
}

func (pf *PacketFragmenter) BuildNextFragment() (*stack.PacketBuffer, int, int, bool) {
	if pf.currentFragment >= pf.fragmentCount {
		panic("BuildNextFragment should not be called again after the last fragment was returned")
	}

	fragPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: pf.reserve,
		Mark:               pf.mark,
	})

	copied := fragPkt.Data().ReadFrom(&pf.data, pf.fragmentPayloadLen)

	offset := pf.fragmentOffset
	pf.fragmentOffset += copied
	pf.currentFragment++
	more := pf.currentFragment != pf.fragmentCount

	return fragPkt, offset, copied, more
}

func (pf *PacketFragmenter) RemainingFragmentCount() int {
	return pf.fragmentCount - pf.currentFragment
}

func (pf *PacketFragmenter) Release() {
	pf.data.Release()
}
