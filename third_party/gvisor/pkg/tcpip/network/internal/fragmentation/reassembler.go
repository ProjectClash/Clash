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
	"math"
	"sort"

	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type hole struct {
	first  uint16
	last   uint16
	filled bool
	final  bool
	pkt *stack.PacketBuffer
}

type reassembler struct {
	reassemblerEntry
	id        FragmentID
	memSize   int
	proto     uint8
	mu        sync.Mutex `state:"nosave"`
	holes     []hole
	filled    int
	done      bool
	createdAt tcpip.MonotonicTime
	pkt       *stack.PacketBuffer
}

func newReassembler(id FragmentID, clock tcpip.Clock) *reassembler {
	r := &reassembler{
		id:        id,
		createdAt: clock.NowMonotonic(),
	}
	r.holes = append(r.holes, hole{
		first:  0,
		last:   math.MaxUint16,
		filled: false,
		final:  true,
	})
	return r
}

func (r *reassembler) process(first, last uint16, more bool, proto uint8, pkt *stack.PacketBuffer) (*stack.PacketBuffer, uint8, bool, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return nil, 0, false, 0, nil
	}

	var holeFound bool
	var memConsumed int
	for i := range r.holes {
		currentHole := &r.holes[i]

		if last < currentHole.first || currentHole.last < first {
			continue
		}
		if first < currentHole.first || currentHole.last < last {
			return nil, 0, false, 0, ErrFragmentOverlap
		}
		if !more {
			if !currentHole.final || currentHole.filled && currentHole.last != last {
				return nil, 0, false, 0, ErrFragmentConflict
			}
		}

		holeFound = true
		if currentHole.filled {
			if first != currentHole.first || last != currentHole.last {
				return nil, 0, false, 0, ErrFragmentOverlap
			}
			continue
		}

		if first > currentHole.first {
			r.holes = append(r.holes, hole{
				first:  currentHole.first,
				last:   first - 1,
				filled: false,
				final:  false,
			})
		}
		if last < currentHole.last && more {
			r.holes = append(r.holes, hole{
				first:  last + 1,
				last:   currentHole.last,
				filled: false,
				final:  currentHole.final,
			})
			currentHole.final = false
		}
		memConsumed = pkt.MemSize()
		r.memSize += memConsumed
		r.holes[i] = hole{
			first:  first,
			last:   last,
			filled: true,
			final:  currentHole.final,
			pkt:    pkt.Clone(),
		}
		r.filled++
		if first == 0 {
			if r.pkt != nil {
				r.pkt.DecRef()
			}
			r.pkt = pkt.Clone()
			r.proto = proto
		}
		break
	}
	if !holeFound {
		return nil, 0, false, 0, ErrFragmentConflict
	}

	if r.filled < len(r.holes) {
		return nil, 0, false, memConsumed, nil
	}

	sort.Slice(r.holes, func(i, j int) bool {
		return r.holes[i].first < r.holes[j].first
	})

	resPkt := r.holes[0].pkt.Clone()
	for i := 1; i < len(r.holes); i++ {
		stack.MergeFragment(resPkt, r.holes[i].pkt)
	}
	return resPkt, r.proto, true, memConsumed, nil
}

func (r *reassembler) checkDoneOrMark() bool {
	r.mu.Lock()
	prev := r.done
	r.done = true
	r.mu.Unlock()
	return prev
}
