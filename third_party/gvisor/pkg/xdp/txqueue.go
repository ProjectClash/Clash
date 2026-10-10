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
	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
)

type TXQueue struct {
	sockfd uint32

	mem []byte

	ring []unix.XDPDesc

	mask uint32

	producer *atomicbitops.Uint32

	consumer *atomicbitops.Uint32

	flags *atomicbitops.Uint32


	cachedProducer uint32
	cachedConsumer uint32
}

func (tq *TXQueue) Reserve(umem *UMEM, toReserve uint32) (nReserved, index uint32) {
	if umem.nFreeFrames < toReserve || tq.free(toReserve) < toReserve {
		return 0, 0
	}
	idx := tq.cachedProducer
	tq.cachedProducer += toReserve
	return toReserve, idx
}

func (tq *TXQueue) free(toReserve uint32) uint32 {
	if available := tq.cachedConsumer - tq.cachedProducer; available >= toReserve {
		return available
	}

	tq.cachedConsumer = tq.consumer.Load()
	tq.cachedConsumer += uint32(len(tq.ring))
	return tq.cachedConsumer - tq.cachedProducer
}

func (tq *TXQueue) Notify() {
	tq.producer.Store(tq.cachedProducer)
	tq.kick()
}

func (tq *TXQueue) Set(index uint32, desc unix.XDPDesc) {
	tq.ring[index&tq.mask] = desc
}
