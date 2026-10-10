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

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd linux netbsd openbsd solaris

package fdchannel

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const sizeofInt32 = int(unsafe.Sizeof(int32(0)))

func NewConnectedSockets() ([2]int, error) {
	return unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
}

type Endpoint struct {
	sockfd int32
	msghdr unix.Msghdr
	cmsg   *unix.Cmsghdr
}

func (ep *Endpoint) Init(sockfd int) {
	cmsgSlice := make([]byte, unix.CmsgSpace(sizeofInt32))
	ep.sockfd = int32(sockfd)
	ep.msghdr.Control = (*byte)(unsafe.Pointer(&cmsgSlice[0]))
	ep.cmsg = (*unix.Cmsghdr)(unsafe.Pointer(&cmsgSlice[0]))
}

func NewEndpoint(sockfd int) *Endpoint {
	ep := &Endpoint{}
	ep.Init(sockfd)
	return ep
}

func (ep *Endpoint) Destroy() {
	unix.Close(int(ep.sockfd))
	ep.sockfd = -1
}

func (ep *Endpoint) Shutdown() {
	unix.Shutdown(int(ep.sockfd), unix.SHUT_RDWR)
}

func (ep *Endpoint) SendFD(fd int) error {
	cmsgLen := unix.CmsgLen(sizeofInt32)
	ep.cmsg.Level = unix.SOL_SOCKET
	ep.cmsg.Type = unix.SCM_RIGHTS
	ep.cmsg.SetLen(cmsgLen)
	*ep.cmsgData() = int32(fd)
	ep.msghdr.SetControllen(cmsgLen)
	_, _, e := unix.Syscall(unix.SYS_SENDMSG, uintptr(ep.sockfd), uintptr(unsafe.Pointer(&ep.msghdr)), 0)
	if e != 0 {
		return e
	}
	return nil
}

func (ep *Endpoint) RecvFD() (int, error) {
	return ep.recvFD(false)
}

func (ep *Endpoint) RecvFDNonblock() (int, error) {
	return ep.recvFD(true)
}

func (ep *Endpoint) recvFD(nonblock bool) (int, error) {
	cmsgLen := unix.CmsgLen(sizeofInt32)
	ep.msghdr.SetControllen(cmsgLen)
	var e unix.Errno
	if nonblock {
		_, _, e = unix.RawSyscall(unix.SYS_RECVMSG, uintptr(ep.sockfd), uintptr(unsafe.Pointer(&ep.msghdr)), unix.MSG_TRUNC|unix.MSG_DONTWAIT)
	} else {
		_, _, e = unix.Syscall(unix.SYS_RECVMSG, uintptr(ep.sockfd), uintptr(unsafe.Pointer(&ep.msghdr)), unix.MSG_TRUNC)
	}
	if e != 0 {
		return -1, e
	}
	if int(ep.msghdr.Controllen) != cmsgLen {
		return -1, fmt.Errorf("received control message has incorrect length: got %d, wanted %d", ep.msghdr.Controllen, cmsgLen)
	}
	if ep.cmsg.Level != unix.SOL_SOCKET || ep.cmsg.Type != unix.SCM_RIGHTS {
		return -1, fmt.Errorf("received control message has incorrect (level, type): got (%v, %v), wanted (%v, %v)", ep.cmsg.Level, ep.cmsg.Type, unix.SOL_SOCKET, unix.SCM_RIGHTS)
	}
	return int(*ep.cmsgData()), nil
}

func (ep *Endpoint) cmsgData() *int32 {
	return (*int32)(unsafe.Pointer(uintptr(unsafe.Pointer(ep.cmsg)) + uintptr(unix.CmsgLen(0))))
}
