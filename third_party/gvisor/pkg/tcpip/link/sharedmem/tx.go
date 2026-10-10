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

package sharedmem

import (
	"math"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/eventfd"
	"github.com/metacubex/gvisor/pkg/tcpip/link/sharedmem/queue"
)

const (
	nilID = math.MaxUint64
)

type tx struct {
	data         []byte
	q            queue.Tx
	ids          idManager
	bufs         bufferManager
	eventFD      eventfd.Eventfd
	sharedData   []byte
	sharedDataFD int
}

func (t *tx) init(bufferSize uint32, c *QueueConfig) error {
	txPipe, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}

	rxPipe, err := getBuffer(c.RxPipeFD)
	if err != nil {
		unix.Munmap(txPipe)
		return err
	}

	data, err := getBuffer(c.DataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		return err
	}

	sharedData, err := getBuffer(c.SharedDataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		unix.Munmap(data)
	}

	t.q.Init(txPipe, rxPipe, sharedDataPointer(sharedData))
	t.ids.init()
	t.bufs.init(0, len(data), int(bufferSize))
	t.data = data
	t.eventFD = c.EventFD
	t.sharedDataFD = c.SharedDataFD
	t.sharedData = sharedData

	return nil
}

func (t *tx) cleanup() {
	a, b := t.q.Bytes()
	unix.Munmap(a)
	unix.Munmap(b)
	unix.Munmap(t.data)
}

func (t *tx) transmit(transmitBuf buffer.Buffer) bool {
	for {
		id, ok := t.q.CompletedPacket()
		if !ok {
			break
		}

		if buf := t.ids.remove(id); buf != nil {
			t.bufs.free(buf)
		}
	}

	bSize := t.bufs.entrySize
	total := uint32(transmitBuf.Size())
	bufCount := (total + bSize - 1) / bSize

	var buf *queue.TxBuffer
	for i := bufCount; i != 0; i-- {
		b := t.bufs.alloc()
		if b == nil {
			if buf != nil {
				t.bufs.free(buf)
			}
			return false
		}
		b.Next = buf
		buf = b
	}

	nBuf := buf
	var dBuf []byte
	transmitBuf.Apply(func(v *buffer.View) {
		for v.Size() > 0 {
			if len(dBuf) == 0 {
				dBuf = t.data[nBuf.Offset:][:nBuf.Size]
				nBuf = nBuf.Next
			}
			n := copy(dBuf, v.AsSlice())
			v.TrimFront(n)
			dBuf = dBuf[n:]
		}
	})

	id := t.ids.add(buf)
	if !t.q.Enqueue(id, total, bufCount, buf) {
		t.ids.remove(id)
		t.bufs.free(buf)
		return false
	}

	return true
}

func (t *tx) notify() {
	if t.q.NotificationsEnabled() {
		t.eventFD.Notify()
	}
}

type idDescriptor struct {
	buf      *queue.TxBuffer
	nextFree uint64
}

type idManager struct {
	ids []idDescriptor

	freeList uint64
}

func (m *idManager) init() {
	m.freeList = nilID
}

func (m *idManager) add(b *queue.TxBuffer) uint64 {
	if i := m.freeList; i != nilID {
		m.ids[i].buf = b
		m.freeList = m.ids[i].nextFree
		return i
	}

	m.ids = append(m.ids, idDescriptor{buf: b})
	return uint64(len(m.ids) - 1)
}

func (m *idManager) remove(i uint64) *queue.TxBuffer {
	if i >= uint64(len(m.ids)) {
		return nil
	}

	desc := &m.ids[i]
	b := desc.buf
	if b == nil {
		return nil
	}

	desc.buf = nil
	desc.nextFree = m.freeList
	m.freeList = i

	return b
}

type bufferManager struct {
	freeList  *queue.TxBuffer
	curOffset uint64
	limit     uint64
	entrySize uint32
}

func (b *bufferManager) init(initialOffset, size, entrySize int) {
	b.freeList = nil
	b.curOffset = uint64(initialOffset)
	b.limit = uint64(initialOffset + size/entrySize*entrySize)
	b.entrySize = uint32(entrySize)
}

func (b *bufferManager) alloc() *queue.TxBuffer {
	if b.freeList != nil {
		d := b.freeList
		b.freeList = d.Next
		d.Next = nil
		return d
	}

	if b.curOffset < b.limit {
		d := &queue.TxBuffer{
			Offset: b.curOffset,
			Size:   b.entrySize,
		}
		b.curOffset += uint64(b.entrySize)
		return d
	}

	return nil
}

func (b *bufferManager) free(d *queue.TxBuffer) {
	last := d
	for last.Next != nil {
		last = last.Next
	}

	last.Next = b.freeList
	b.freeList = d
}
