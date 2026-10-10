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

//go:build linux
// +build linux

package sighandling

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/abi/linux"
)

func IgnoreChildStop() error {
	var sa linux.SigAction

	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGCHLD), 0, uintptr(unsafe.Pointer(&sa)), linux.SignalSetSize, 0, 0); e != 0 {
		return e
	}
	sa.Flags |= linux.SA_NOCLDSTOP
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGCHLD), uintptr(unsafe.Pointer(&sa)), 0, linux.SignalSetSize, 0, 0); e != 0 {
		return e
	}

	return nil
}

func ReplaceSignalHandler(sig unix.Signal, handler uintptr, previous *uintptr) error {
	var sa linux.SigAction
	const maskLen = 8

	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), 0, uintptr(unsafe.Pointer(&sa)), maskLen, 0, 0); e != 0 {
		return e
	}

	if sa.Handler == 0 {
		return fmt.Errorf("previous handler for signal %x isn't set", sig)
	}

	*previous = uintptr(sa.Handler)

	sa.Handler = uint64(handler)
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&sa)), 0, maskLen, 0, 0); e != 0 {
		return e
	}

	return nil
}

func KillItself() error {
	pid := os.Getpid()
	tid, _, _ := unix.RawSyscall(unix.SYS_GETTID, 0, 0, 0)
	info := linux.SignalInfo{Code: linux.SI_KERNEL}
	if _, _, e := unix.RawSyscall6(
		unix.SYS_RT_TGSIGQUEUEINFO,
		uintptr(pid), uintptr(tid),
		uintptr(linux.SIGKILL),
		uintptr(unsafe.Pointer(&info)),
		0, 0,
	); e != 0 {
		return e
	}
	panic("unreachable")
}
