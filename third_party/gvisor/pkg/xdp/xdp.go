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
	"math/bits"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/cleanup"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/memutil"
)

type ControlBlock struct {
	UMEM       UMEM
	Fill       FillQueue
	RX         RXQueue
	TX         TXQueue
	Completion CompletionQueue
}

type Opts struct {
	NFrames       uint32
	FrameSize     uint32
	NDescriptors  uint32
	Bind          bool
	UseNeedWakeup bool
}

func DefaultOpts() Opts {
	return Opts{
		NFrames: 4096,
		FrameSize:    4096,
		NDescriptors: 2048,
	}
}

func New(ifaceIdx, queueID uint32, opts Opts) (*ControlBlock, error) {
	sockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP socket: %v", err)
	}
	return NewFromSocket(sockfd, ifaceIdx, queueID, opts)
}

func NewFromSocket(sockfd int, ifaceIdx, queueID uint32, opts Opts) (*ControlBlock, error) {
	if opts.FrameSize != 2048 && opts.FrameSize != 4096 {
		return nil, fmt.Errorf("invalid frame size %d: must be either 2048 or 4096", opts.FrameSize)
	}
	if bits.OnesCount32(opts.NDescriptors) != 1 {
		return nil, fmt.Errorf("invalid number of descriptors %d: must be a power of 2", opts.NDescriptors)
	}

	var cb ControlBlock

	var zerofd uintptr
	umemMemory, err := memutil.MapSlice(
		0,
		uintptr(opts.NFrames*opts.FrameSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
		zerofd-1,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap umem: %v", err)
	}
	cleanup := cleanup.Make(func() {
		memutil.UnmapSlice(umemMemory)
	})

	if sliceBackingPointer(umemMemory)%uintptr(unix.Getpagesize()) != 0 {
		return nil, fmt.Errorf("UMEM is not page aligned (address 0x%x)", sliceBackingPointer(umemMemory))
	}

	cb.UMEM = UMEM{
		mem:            umemMemory,
		sockfd:         uint32(sockfd),
		frameAddresses: make([]uint64, opts.NFrames),
		nFreeFrames:    opts.NFrames,
		frameMask:      ^(uint64(opts.FrameSize) - 1),
	}

	for i := range cb.UMEM.frameAddresses {
		cb.UMEM.frameAddresses[i] = uint64(i) * uint64(opts.FrameSize)
	}

	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		return nil, fmt.Errorf("failed to get rlimit for memlock: %v", err)
	}
	if rlimit.Cur < uint64(len(cb.UMEM.mem)) {
		log.Infof("UMEM size (%d) may exceed RLIMIT_MEMLOCK (%+v) and cause registration to fail", len(cb.UMEM.mem), rlimit)
	}

	reg := unix.XDPUmemReg{
		Addr: uint64(sliceBackingPointer(umemMemory)),
		Len:  uint64(len(umemMemory)),
		Size: opts.FrameSize,
		Headroom: 0,
		Flags: 0,
	}
	if err := registerUMEM(sockfd, reg); err != nil {
		return nil, fmt.Errorf("failed to register UMEM: %v", err)
	}

	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register fill ring: %v", err)
	}
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register completion ring: %v", err)
	}
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_RX_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register RX queue: %v", err)
	}
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_TX_RING, int(opts.NDescriptors)); err != nil {
		return nil, fmt.Errorf("failed to register TX queue: %v", err)
	}

	off, err := getOffsets(sockfd)
	if err != nil {
		return nil, fmt.Errorf("failed to get offsets: %v", err)
	}

	fillQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Fr.Desc+uint64(opts.NDescriptors)*sizeOfFillQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_UMEM_PGOFF_FILL_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap fill queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(fillQueueMem)
	})
	cb.Fill = FillQueue{
		mem:            fillQueueMem,
		mask:           opts.NDescriptors - 1,
		cachedConsumer: opts.NDescriptors,
	}
	cb.Fill.init(off, opts)

	completionQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Cr.Desc+uint64(opts.NDescriptors)*sizeOfCompletionQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_UMEM_PGOFF_COMPLETION_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap completion queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(completionQueueMem)
	})
	cb.Completion = CompletionQueue{
		mem:  completionQueueMem,
		mask: opts.NDescriptors - 1,
	}
	cb.Completion.init(off, opts)

	rxQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Rx.Desc+uint64(opts.NDescriptors)*sizeOfRXQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_PGOFF_RX_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap RX queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(rxQueueMem)
	})
	cb.RX = RXQueue{
		mem:  rxQueueMem,
		mask: opts.NDescriptors - 1,
	}
	cb.RX.init(off, opts)

	txQueueMem, err := memutil.MapSlice(
		0,
		uintptr(off.Tx.Desc+uint64(opts.NDescriptors)*sizeOfTXQueueDesc()),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
		uintptr(sockfd),
		unix.XDP_PGOFF_TX_RING,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap tx queue: %v", err)
	}
	cleanup.Add(func() {
		memutil.UnmapSlice(txQueueMem)
	})
	cb.TX = TXQueue{
		sockfd:         uint32(sockfd),
		mem:            txQueueMem,
		mask:           opts.NDescriptors - 1,
		cachedConsumer: opts.NDescriptors,
	}
	cb.TX.init(off, opts)

	if opts.Bind {
		if err := Bind(sockfd, ifaceIdx, queueID, opts.UseNeedWakeup); err != nil {
			return nil, fmt.Errorf("failed to bind to interface %d: %v", ifaceIdx, err)
		}
	}

	cleanup.Release()
	return &cb, nil
}

func Bind(sockfd int, ifindex, queueID uint32, useNeedWakeup bool) error {
	var flags uint16
	if useNeedWakeup {
		flags |= unix.XDP_USE_NEED_WAKEUP
	}
	addr := unix.SockaddrXDP{
		Flags:   flags,
		Ifindex: ifindex,
		QueueID: queueID,
		SharedUmemFD: 0,
	}
	return unix.Bind(sockfd, &addr)
}
