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

package queue

import (
	"encoding/binary"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/tcpip/link/sharedmem/pipe"
)

const (
	packetID       = 0
	packetSize     = 8
	packetReserved = 12

	sizeOfPacketHeader = 16

	bufferOffset = 0
	bufferSize   = 8

	sizeOfBufferDescriptor = 12
)

type TxBuffer struct {
	Next   *TxBuffer
	Offset uint64
	Size   uint32
}

type Tx struct {
	tx                 pipe.Tx
	rx                 pipe.Rx
	sharedEventFDState *atomicbitops.Uint32
}

func (t *Tx) Init(tx, rx []byte, sharedEventFDState *atomicbitops.Uint32) {
	t.tx.Init(tx)
	t.rx.Init(rx)
	t.sharedEventFDState = sharedEventFDState
}

func (t *Tx) NotificationsEnabled() bool {
	return t.sharedEventFDState.Load() != EventFDDisabled
}

func (t *Tx) Enqueue(id uint64, totalDataLen, bufferCount uint32, buffer *TxBuffer) bool {
	totalLen := sizeOfPacketHeader + uint64(bufferCount)*sizeOfBufferDescriptor

	b := t.tx.Push(totalLen)
	if b == nil {
		return false
	}

	binary.LittleEndian.PutUint64(b[packetID:], id)
	binary.LittleEndian.PutUint32(b[packetSize:], totalDataLen)
	binary.LittleEndian.PutUint32(b[packetReserved:], 0)

	offset := sizeOfPacketHeader
	for i := bufferCount; i != 0; i-- {
		binary.LittleEndian.PutUint64(b[offset+bufferOffset:], buffer.Offset)
		binary.LittleEndian.PutUint32(b[offset+bufferSize:], buffer.Size)
		offset += sizeOfBufferDescriptor
		buffer = buffer.Next
	}

	t.tx.Flush()

	return true
}

func (t *Tx) CompletedPacket() (id uint64, ok bool) {
	for {
		b := t.rx.Pull()
		if b == nil {
			return 0, false
		}

		if len(b) != 8 {
			t.rx.Flush()
			log.Warningf("Ignoring completed packet: size (%v) is less than expected (%v)", len(b), 8)
			continue
		}

		v := binary.LittleEndian.Uint64(b)

		t.rx.Flush()

		return v, true
	}
}

func (t *Tx) Bytes() (tx, rx []byte) {
	return t.tx.Bytes(), t.rx.Bytes()
}

type TxPacketInfo struct {
	ID          uint64
	Size        uint32
	Reserved    uint32
	BufferCount int
}

func DecodeTxPacketHeader(b []byte) TxPacketInfo {
	return TxPacketInfo{
		ID:          binary.LittleEndian.Uint64(b[packetID:]),
		Size:        binary.LittleEndian.Uint32(b[packetSize:]),
		Reserved:    binary.LittleEndian.Uint32(b[packetReserved:]),
		BufferCount: (len(b) - sizeOfPacketHeader) / sizeOfBufferDescriptor,
	}
}

func DecodeTxBufferHeader(b []byte, i int) TxBuffer {
	b = b[sizeOfPacketHeader+i*sizeOfBufferDescriptor:]
	return TxBuffer{
		Offset: binary.LittleEndian.Uint64(b[bufferOffset:]),
		Size:   binary.LittleEndian.Uint32(b[bufferSize:]),
	}
}

func EncodeTxCompletion(b []byte, id uint64) {
	binary.LittleEndian.PutUint64(b, id)
}
