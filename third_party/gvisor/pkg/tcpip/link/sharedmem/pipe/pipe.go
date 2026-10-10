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

import (
	"math"
)

const (
	jump           uint64 = math.MaxUint32 + 1
	offsetMask     uint64 = math.MaxUint32
	revolutionMask uint64 = ^offsetMask

	sizeOfSlotHeader        = 8
	slotFree         uint64 = 1 << 63
	slotSizeMask     uint64 = math.MaxUint32
)

func payloadToSlotSize(payloadSize uint64) uint64 {
	s := sizeOfSlotHeader + payloadSize
	return (s + sizeOfSlotHeader - 1) &^ (sizeOfSlotHeader - 1)
}

func slotToPayloadSize(offset uint64) uint64 {
	return offset - sizeOfSlotHeader
}

type pipe struct {
	buffer []byte
}

func (p *pipe) init(b []byte) {
	p.buffer = b[:len(b)&^(sizeOfSlotHeader-1)]
}

func (p *pipe) data(idx uint64, size uint64) []byte {
	return p.buffer[(idx&offsetMask)+sizeOfSlotHeader:][:size]
}
