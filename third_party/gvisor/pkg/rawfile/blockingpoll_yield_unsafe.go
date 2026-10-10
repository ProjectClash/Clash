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

//go:build ((linux && amd64) || (linux && arm64)) && go1.18
// +build linux,amd64 linux,arm64
// +build go1.18

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package rawfile

import (
	_ "unsafe"

	"golang.org/x/sys/unix"
)

// BlockingPoll on amd64/arm64 makes the ppoll() syscall while calling the
// version of entersyscall that relinquishes the P so that other Gs can
// run. This is meant to be called in cases when the syscall is expected to
// block. On non amd64/arm64 platforms it just forwards to the ppoll() system
// call.
//
//go:noescape
func BlockingPoll(fds *PollEvent, nfds int, timeout *unix.Timespec) (int, unix.Errno)




//go:linkname entersyscallblock runtime.entersyscallblock
func entersyscallblock()

//go:linkname exitsyscall runtime.exitsyscall
func exitsyscall()


//go:nosplit
func callEntersyscallblock() {
	entersyscallblock()
}

//go:nosplit
func callExitsyscall() {
	exitsyscall()
}
