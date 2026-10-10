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
	"fmt"
	"math/bits"
	"os"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/abi/linux"
	"github.com/metacubex/gvisor/pkg/memutil"
)

var (
	pageSize = os.Getpagesize()
	pageMask = pageSize - 1
)

func init() {
	if bits.OnesCount(uint(pageSize)) != 1 {
		panic(fmt.Sprintf("system page size (%d) is not a power of 2", pageSize))
	}
	if uintptr(pageSize) < PacketHeaderBytes {
		panic(fmt.Sprintf("system page size (%d) is less than packet header size (%d)", pageSize, PacketHeaderBytes))
	}
}

type PacketWindowDescriptor struct {
	FD int

	Offset int64

	Length int
}

func PacketWindowLengthForDataCap(dataCap uint32) int {
	return roundUpToPage(int(dataCap) + int(PacketHeaderBytes))
}

func roundUpToPage(x int) int {
	return (x + pageMask) &^ pageMask
}

type PacketWindowAllocator struct {
	fd        int
	nextAlloc int64
	fileSize  int64
}

func (pwa *PacketWindowAllocator) Init() error {
	fd, err := memutil.CreateMemFD("flipcall_packet_windows", linux.MFD_CLOEXEC|linux.MFD_ALLOW_SEALING)
	if err != nil {
		return fmt.Errorf("failed to create memfd: %v", err)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_FCNTL, uintptr(fd), linux.F_ADD_SEALS, linux.F_SEAL_SHRINK|linux.F_SEAL_SEAL); e != 0 {
		unix.Close(fd)
		return fmt.Errorf("failed to apply memfd seals: %v", e)
	}
	pwa.fd = fd
	return nil
}

func NewPacketWindowAllocator() (*PacketWindowAllocator, error) {
	var pwa PacketWindowAllocator
	if err := pwa.Init(); err != nil {
		return nil, err
	}
	return &pwa, nil
}

func (pwa *PacketWindowAllocator) Destroy() {
	unix.Close(pwa.fd)
}

func (pwa *PacketWindowAllocator) FD() int {
	return pwa.fd
}

func (pwa *PacketWindowAllocator) Allocate(size int) (PacketWindowDescriptor, error) {
	if size <= 0 {
		return PacketWindowDescriptor{}, fmt.Errorf("invalid size: %d", size)
	}
	size = roundUpToPage(size)
	if size <= 0 {
		return PacketWindowDescriptor{}, fmt.Errorf("size %d overflows after rounding up to page size", size)
	}
	end := pwa.nextAlloc + int64(size)
	if err := pwa.ensureFileSize(end); err != nil {
		return PacketWindowDescriptor{}, err
	}
	start := pwa.nextAlloc
	pwa.nextAlloc = end
	return PacketWindowDescriptor{
		FD:     pwa.FD(),
		Offset: start,
		Length: size,
	}, nil
}

func (pwa *PacketWindowAllocator) ensureFileSize(min int64) error {
	if min <= 0 {
		return fmt.Errorf("file size would overflow")
	}
	if pwa.fileSize >= min {
		return nil
	}
	newSize := 2 * pwa.fileSize
	if newSize == 0 {
		newSize = int64(pageSize)
	}
	for newSize < min {
		newNewSize := newSize * 2
		if newNewSize <= 0 {
			return fmt.Errorf("file size would overflow")
		}
		newSize = newNewSize
	}
	if err := unix.Ftruncate(pwa.FD(), newSize); err != nil {
		return fmt.Errorf("ftruncate failed: %v", err)
	}
	pwa.fileSize = newSize
	return nil
}
