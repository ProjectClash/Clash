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

type Rx struct {
	p pipe

	tail uint64
	head uint64
}

func (r *Rx) Init(b []byte) {
	r.p.init(b)
	r.tail = 0xfffffffe * jump
	r.head = r.tail
}

func (r *Rx) Pull() []byte {
	if r.head == r.tail+jump {
		return nil
	}

	header := r.p.readAtomic(r.head)
	if header&slotFree != 0 {
		return nil
	}

	payloadSize := header & slotSizeMask
	newHead := r.head + payloadToSlotSize(payloadSize)
	headWrap := (r.head & revolutionMask) | uint64(len(r.p.buffer))

	if int64(newHead-headWrap) >= 0 {
		if int64(newHead-(r.tail+jump)) > 0 {
			return nil
		}
		if newHead&offsetMask != 0 {
			return nil
		}

		if r.tail == r.head {
			r.p.writeAtomic(r.head, slotFree|slotToPayloadSize(newHead-r.head))
			r.tail = newHead
		}

		r.head = newHead
		return r.Pull()
	}

	b := r.p.data(r.head, payloadSize)
	r.head = newHead
	return b
}

func (r *Rx) Flush() {
	if r.head == r.tail {
		return
	}
	r.p.writeAtomic(r.tail, slotFree|slotToPayloadSize(r.head-r.tail))
	r.tail = r.head
}

func (r *Rx) Abort() {
	r.head = r.tail
}

func (r *Rx) Bytes() []byte {
	return r.p.buffer
}
