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
	"fmt"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/sync"
)



type UMEM struct {
	mem []byte

	sockfd uint32

	frameMask uint64

	mu sync.Mutex

	frameAddresses []uint64

	nFreeFrames uint32
}

func (um *UMEM) SockFD() uint32 {
	return um.sockfd
}

func (um *UMEM) Lock() {
	um.mu.Lock()
}

func (um *UMEM) Unlock() {
	um.mu.Unlock()
}

func (um *UMEM) FreeFrame(addr uint64) {
	um.frameAddresses[um.nFreeFrames] = addr
	um.nFreeFrames++
}

func (um *UMEM) AllocFrame() uint64 {
	um.nFreeFrames--
	return um.frameAddresses[um.nFreeFrames] & um.frameMask
}

func (um *UMEM) Get(desc unix.XDPDesc) []byte {
	end := desc.Addr + uint64(desc.Len)
	if desc.Addr&um.frameMask != (end-1)&um.frameMask {
		panic(fmt.Sprintf("UMEM (%+v) access crosses frame boundaries: %+v", um, desc))
	}
	return um.mem[desc.Addr:end]
}
