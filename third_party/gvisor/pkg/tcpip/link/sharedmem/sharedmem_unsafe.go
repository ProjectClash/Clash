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

package sharedmem

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/memutil"
)

func sharedDataPointer(sharedData []byte) *atomicbitops.Uint32 {
	return (*atomicbitops.Uint32)(unsafe.Pointer(&sharedData[0:4][0]))
}

func getBuffer(fd int) ([]byte, error) {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return nil, err
	}

	if s.Size > int64(^uint(0)>>1) {
		return nil, unix.EDOM
	}

	addr, err := memutil.MapFile(0, uintptr(s.Size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FILE, uintptr(fd), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to map memory for buffer fd: %d, error: %s", fd, err)
	}

	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(s.Size))

	return b, nil
}
