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

package safecopy

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/errors"
	"github.com/metacubex/gvisor/pkg/errors/linuxerr"
	"github.com/metacubex/gvisor/pkg/sighandling"
)

type SegvError struct {
	Addr uintptr
}

func (e SegvError) Error() string {
	return fmt.Sprintf("SIGSEGV at %#x", e.Addr)
}

type BusError struct {
	Addr uintptr
}

func (e BusError) Error() string {
	return fmt.Sprintf("SIGBUS at %#x", e.Addr)
}

type AlignmentError struct {
	Addr uintptr

	Alignment uintptr
}

func (e AlignmentError) Error() string {
	return fmt.Sprintf("address %#x is not aligned to a %d-byte boundary", e.Addr, e.Alignment)
}

var (
	memcpyBegin               uintptr
	memcpyEnd                 uintptr
	memclrBegin               uintptr
	memclrEnd                 uintptr
	swapUint32Begin           uintptr
	swapUint32End             uintptr
	swapUint64Begin           uintptr
	swapUint64End             uintptr
	compareAndSwapUint32Begin uintptr
	compareAndSwapUint32End   uintptr
	loadUint32Begin           uintptr
	loadUint32End             uintptr

	savedSigSegVHandler uintptr

	savedSigBusHandler uintptr
)

func signalHandler()

func addrOfSignalHandler() uintptr

func FindEndAddress(begin uintptr) uintptr {
	f := runtime.FuncForPC(begin)
	if f != nil {
		for p := begin; ; p++ {
			g := runtime.FuncForPC(p)
			if f != g {
				return p
			}
		}
	}
	return begin
}

func initializeAddresses() {
	memcpyBegin = addrOfMemcpy()
	memcpyEnd = FindEndAddress(memcpyBegin)
	memclrBegin = addrOfMemclr()
	memclrEnd = FindEndAddress(memclrBegin)
	swapUint32Begin = addrOfSwapUint32()
	swapUint32End = FindEndAddress(swapUint32Begin)
	swapUint64Begin = addrOfSwapUint64()
	swapUint64End = FindEndAddress(swapUint64Begin)
	compareAndSwapUint32Begin = addrOfCompareAndSwapUint32()
	compareAndSwapUint32End = FindEndAddress(compareAndSwapUint32Begin)
	loadUint32Begin = addrOfLoadUint32()
	loadUint32End = FindEndAddress(loadUint32Begin)
	initializeArchAddresses()
}

func init() {
	initializeAddresses()
	if err := sighandling.ReplaceSignalHandler(unix.SIGSEGV, addrOfSignalHandler(), &savedSigSegVHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for SIGSEGV: %v", err))
	}
	if err := sighandling.ReplaceSignalHandler(unix.SIGBUS, addrOfSignalHandler(), &savedSigBusHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for SIGBUS: %v", err))
	}
	linuxerr.AddErrorUnwrapper(func(e error) (*errors.Error, bool) {
		switch e.(type) {
		case SegvError, BusError, AlignmentError:
			return linuxerr.EFAULT, true
		default:
			return nil, false
		}
	})
}
