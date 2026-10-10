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

type CompletionQueue struct {
	mem []byte

	ring []uint64

	mask uint32

	producer *atomicbitops.Uint32

	consumer *atomicbitops.Uint32

	flags *atomicbitops.Uint32


	cachedProducer uint32
	cachedConsumer uint32
}

func (cq *CompletionQueue) Peek() (nAvailable, index uint32) {
	entries := cq.free()
	index = cq.cachedConsumer
	cq.cachedConsumer += entries
	return entries, index
}

func (cq *CompletionQueue) free() uint32 {
	entries := cq.cachedProducer - cq.cachedConsumer
	if entries == 0 {
		cq.cachedProducer = cq.producer.Load()
		entries = cq.cachedProducer - cq.cachedConsumer
	}
	return entries
}

func (cq *CompletionQueue) Release(nDone uint32) {
	cq.consumer.Store(cq.consumer.RacyLoad() + nDone)
}

func (cq *CompletionQueue) Get(index uint32) uint64 {
	return cq.ring[index&cq.mask]
}

func (cq *CompletionQueue) FreeAll(umem *UMEM) {
	available, index := cq.Peek()
	if available < 1 {
		return
	}
	for i := uint32(0); i < available; i++ {
		umem.FreeFrame(cq.Get(index + i))
	}
	cq.Release(available)
}
