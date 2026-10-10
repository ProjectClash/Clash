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

type RXQueue struct {
	mem []byte

	ring []unix.XDPDesc

	mask uint32

	producer *atomicbitops.Uint32

	consumer *atomicbitops.Uint32

	flags *atomicbitops.Uint32


	cachedProducer uint32
	cachedConsumer uint32
}

func (rq *RXQueue) Peek() (nReceived, index uint32) {
	entries := rq.free()
	index = rq.cachedConsumer
	rq.cachedConsumer += entries
	return entries, index
}

func (rq *RXQueue) free() uint32 {
	entries := rq.cachedProducer - rq.cachedConsumer
	if entries == 0 {
		rq.cachedProducer = rq.producer.Load()
		entries = rq.cachedProducer - rq.cachedConsumer
	}
	return entries
}

func (rq *RXQueue) Release(nDone uint32) {
	rq.consumer.Store(rq.consumer.RacyLoad() + nDone)
}

func (rq *RXQueue) Get(index uint32) unix.XDPDesc {
	return rq.ring[index&rq.mask]
}
