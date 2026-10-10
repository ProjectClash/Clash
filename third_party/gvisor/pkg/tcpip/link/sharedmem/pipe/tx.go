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

package pipe

type Tx struct {
	p              pipe
	maxPayloadSize uint64

	head uint64
	tail uint64
	next uint64

	tailHeader uint64
}

func (t *Tx) Init(b []byte) {
	t.p.init(b)
	t.maxPayloadSize = uint64(len(t.p.buffer)) - 2*sizeOfSlotHeader
	t.tail = 0xfffffffe * jump
	t.next = t.tail
	t.head = t.tail + jump
	t.p.write(t.tail, slotFree)
}

func (t *Tx) Capacity(recordSize uint64) uint64 {
	available := uint64(len(t.p.buffer)) - sizeOfSlotHeader
	entryLen := payloadToSlotSize(recordSize)
	return available / entryLen
}

func (t *Tx) Push(payloadSize uint64) []byte {
	if payloadSize > t.maxPayloadSize {
		return nil
	}

	messageAhead := t.next != t.tail
	totalLen := payloadToSlotSize(payloadSize)
	newNext := t.next + totalLen
	nextWrap := (t.next & revolutionMask) | uint64(len(t.p.buffer))
	if int64(newNext-nextWrap) >= 0 {
		newNext = (newNext & revolutionMask) + jump
		if !t.reclaim(newNext) {
			return nil
		}
		wrappingPayloadSize := slotToPayloadSize(newNext - t.next)
		oldNext := t.next
		t.next = newNext
		if messageAhead {
			t.p.write(oldNext, wrappingPayloadSize)
		} else {
			t.tailHeader = wrappingPayloadSize
			t.Flush()
		}
		return t.Push(payloadSize)
	}

	if !t.reclaim(newNext) {
		return nil
	}

	if messageAhead {
		t.p.write(t.next, payloadSize)
	} else {
		t.tailHeader = payloadSize
	}

	b := t.p.data(t.next, payloadSize)
	t.next = newNext

	return b
}

func (t *Tx) reclaim(newNext uint64) bool {
	for int64(newNext-t.head) > 0 {
		header := t.p.readAtomic(t.head)
		if header&slotFree == 0 {
			return false
		}

		payloadSize := header & slotSizeMask
		newHead := t.head + payloadToSlotSize(payloadSize)

		if int64(newHead-t.tail) > int64(jump) || newHead&offsetMask >= uint64(len(t.p.buffer)) {
			return false
		}

		t.head = newHead
	}

	return true
}

func (t *Tx) Abort() {
	t.next = t.tail
}

func (t *Tx) Flush() {
	if t.next == t.tail {
		return
	}

	if t.next != t.head {
		t.p.write(t.next, slotFree)
	}

	t.p.writeAtomic(t.tail, t.tailHeader)
	t.tail = t.next
}

func (t *Tx) Bytes() []byte {
	return t.p.buffer
}
