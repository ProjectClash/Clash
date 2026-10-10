// Copyright 2019 The gVisor Authors.
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

package flipcall

import (
	"unsafe"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/sync"
)

const (
	PacketHeaderBytes = 16
)

func (ep *Endpoint) connState() *atomicbitops.Uint32 {
	return (*atomicbitops.Uint32)(unsafe.Pointer(ep.packet))
}

func (ep *Endpoint) dataLen() *atomicbitops.Uint32 {
	return (*atomicbitops.Uint32)(unsafe.Pointer(ep.packet + 4))
}

func (ep *Endpoint) Data() []byte {
	ptr := unsafe.Pointer(ep.packet + PacketHeaderBytes)
	return unsafe.Slice((*byte)(ptr), int(ep.dataCap))
}

var ioSync int64

func raceBecomeActive() {
	if sync.RaceEnabled {
		sync.RaceAcquire(unsafe.Pointer(&ioSync))
	}
}

func raceBecomeInactive() {
	if sync.RaceEnabled {
		sync.RaceReleaseMerge(unsafe.Pointer(&ioSync))
	}
}
