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
	postedOffset           = 0
	postedSize             = 8
	postedRemainingInGroup = 12
	postedUserData         = 16
	postedID               = 24

	sizeOfPostedBuffer = 32

	consumedPacketSize     = 0
	consumedPacketReserved = 4

	sizeOfConsumedPacketHeader = 8

	consumedOffset   = 0
	consumedSize     = 8
	consumedUserData = 12
	consumedID       = 20

	sizeOfConsumedBuffer = 28

	EventFDUninitialized = 0
	EventFDDisabled = 1
	EventFDEnabled = 2
)

type RxBuffer struct {
	Offset   uint64
	Size     uint32
	ID       uint64
	UserData uint64
}

type Rx struct {
	tx                 pipe.Tx
	rx                 pipe.Rx
	sharedEventFDState *atomicbitops.Uint32
}

func (r *Rx) Init(tx, rx []byte, sharedEventFDState *atomicbitops.Uint32) {
	r.sharedEventFDState = sharedEventFDState
	r.tx.Init(tx)
	r.rx.Init(rx)
}

func (r *Rx) EnableNotification() {
	r.sharedEventFDState.Store(EventFDEnabled)
}

func (r *Rx) DisableNotification() {
	r.sharedEventFDState.Store(EventFDDisabled)
}

func (r *Rx) PostedBuffersLimit() uint64 {
	return r.tx.Capacity(sizeOfPostedBuffer)
}

func (r *Rx) PostBuffers(buffers []RxBuffer) bool {
	for i := range buffers {
		b := r.tx.Push(sizeOfPostedBuffer)
		if b == nil {
			r.tx.Abort()
			return false
		}

		pb := &buffers[i]
		binary.LittleEndian.PutUint64(b[postedOffset:], pb.Offset)
		binary.LittleEndian.PutUint32(b[postedSize:], pb.Size)
		binary.LittleEndian.PutUint32(b[postedRemainingInGroup:], 0)
		binary.LittleEndian.PutUint64(b[postedUserData:], pb.UserData)
		binary.LittleEndian.PutUint64(b[postedID:], pb.ID)
	}

	r.tx.Flush()
	return true
}

func (r *Rx) Dequeue(bufs []RxBuffer) ([]RxBuffer, uint32) {
	for {
		outBufs := bufs
		b := r.rx.Pull()
		if b == nil {
			return bufs, 0
		}

		if len(b) < sizeOfConsumedPacketHeader {
			log.Warningf("Ignoring packet header: size (%v) is less than header size (%v)", len(b), sizeOfConsumedPacketHeader)
			r.rx.Flush()
			continue
		}

		totalDataSize := binary.LittleEndian.Uint32(b[consumedPacketSize:])

		count := (len(b) - sizeOfConsumedPacketHeader) / sizeOfConsumedBuffer
		offset := sizeOfConsumedPacketHeader
		buffersSize := uint32(0)
		for i := count; i > 0; i-- {
			s := binary.LittleEndian.Uint32(b[offset+consumedSize:])
			buffersSize += s
			if buffersSize < s {
				totalDataSize = 1
				buffersSize = 0
				break
			}

			outBufs = append(outBufs, RxBuffer{
				Offset: binary.LittleEndian.Uint64(b[offset+consumedOffset:]),
				Size:   s,
				ID:     binary.LittleEndian.Uint64(b[offset+consumedID:]),
			})

			offset += sizeOfConsumedBuffer
		}

		r.rx.Flush()

		if buffersSize < totalDataSize {
			log.Warningf("Ignoring packet: actual data size (%v) less than expected size (%v)", buffersSize, totalDataSize)
			continue
		}

		return outBufs, totalDataSize
	}
}

func (r *Rx) Bytes() (tx, rx []byte) {
	return r.tx.Bytes(), r.rx.Bytes()
}

func DecodeRxBufferHeader(b []byte) RxBuffer {
	return RxBuffer{
		Offset:   binary.LittleEndian.Uint64(b[postedOffset:]),
		Size:     binary.LittleEndian.Uint32(b[postedSize:]),
		ID:       binary.LittleEndian.Uint64(b[postedID:]),
		UserData: binary.LittleEndian.Uint64(b[postedUserData:]),
	}
}

func RxCompletionSize(count int) uint64 {
	return sizeOfConsumedPacketHeader + uint64(count)*sizeOfConsumedBuffer
}

func EncodeRxCompletion(b []byte, size, reserved uint32) {
	binary.LittleEndian.PutUint32(b[consumedPacketSize:], size)
	binary.LittleEndian.PutUint32(b[consumedPacketReserved:], reserved)
}

func EncodeRxCompletionBuffer(b []byte, i int, rxb RxBuffer) {
	b = b[RxCompletionSize(i):]
	binary.LittleEndian.PutUint64(b[consumedOffset:], rxb.Offset)
	binary.LittleEndian.PutUint32(b[consumedSize:], rxb.Size)
	binary.LittleEndian.PutUint64(b[consumedUserData:], rxb.UserData)
	binary.LittleEndian.PutUint64(b[consumedID:], rxb.ID)
}
