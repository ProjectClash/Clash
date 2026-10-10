// Copyright 2022 The gVisor Authors.
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

//go:build amd64 || arm64
// +build amd64 arm64

package xdp

import (
	"github.com/metacubex/gvisor/pkg/atomicbitops"
)

type FillQueue struct {
	mem []byte

	ring []uint64

	mask uint32

	producer *atomicbitops.Uint32

	consumer *atomicbitops.Uint32

	flags *atomicbitops.Uint32


	cachedProducer uint32
	cachedConsumer uint32
}

func (fq *FillQueue) free(toReserve uint32) uint32 {
	if available := fq.cachedConsumer - fq.cachedProducer; available >= toReserve {
		return available
	}

	fq.cachedConsumer = fq.consumer.Load()
	fq.cachedConsumer += uint32(len(fq.ring))
	return fq.cachedConsumer - fq.cachedProducer
}

func (fq *FillQueue) Notify() {
	fq.producer.Store(fq.cachedProducer)
}

func (fq *FillQueue) Set(index uint32, addr uint64) {
	fq.ring[index&fq.mask] = addr
}

func (fq *FillQueue) FillAll(umem *UMEM) {
	available := fq.free(umem.nFreeFrames)
	if available == 0 {
		return
	}
	if available > umem.nFreeFrames {
		available = umem.nFreeFrames
	}

	index := fq.cachedProducer
	fq.cachedProducer += available
	for i := uint32(0); i < available; i++ {
		fq.Set(index+i, umem.AllocFrame())
	}
	fq.Notify()
}
