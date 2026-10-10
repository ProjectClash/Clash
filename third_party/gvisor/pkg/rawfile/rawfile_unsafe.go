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

package rawfile

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const SizeofIovec = unsafe.Sizeof(unix.Iovec{})

const MaxIovs = 1024

func IovecFromBytes(bs []byte) unix.Iovec {
	iov := unix.Iovec{
		Base: &bs[0],
	}
	iov.SetLen(len(bs))
	return iov
}

func bytesFromIovec(iov unix.Iovec) []byte {
	ptr := unsafe.Pointer(iov.Base)
	return unsafe.Slice((*byte)(ptr), int(iov.Len))
}

func AppendIovecFromBytes(iovs []unix.Iovec, bs []byte, max int) []unix.Iovec {
	if len(bs) == 0 {
		return iovs
	}
	if len(iovs) < max {
		return append(iovs, IovecFromBytes(bs))
	}
	iovs[len(iovs)-1] = IovecFromBytes(append(bytesFromIovec(iovs[len(iovs)-1]), bs...))
	return iovs
}

type MMsgHdr struct {
	Msg unix.Msghdr
	Len uint32
	_   [4]byte
}

const SizeofMMsgHdr = unsafe.Sizeof(MMsgHdr{})

func GetMTU(name string) (uint32, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

func NonBlockingWrite(fd int, buf []byte) unix.Errno {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	_, _, e := unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	return e
}

func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) unix.Errno {
	iovecLen := uintptr(len(iovec))
	_, _, e := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), iovecLen)
	return e
}

func NonBlockingSendMMsg(fd int, msgHdrs []MMsgHdr) (int, unix.Errno) {
	n, _, e := unix.RawSyscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
	return int(n), e
}

type PollEvent struct {
	FD      int32
	Events  int16
	Revents int16
}

func BlockingRead(fd int, b []byte) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if e == 0 {
			return int(n), 0
		}

		event := PollEvent{
			FD:     int32(fd),
			Events: 1,
		}

		_, e = BlockingPoll(&event, 1, nil)
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingReadvUntilStopped(efd int, fd int, iovecs []unix.Iovec) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e == 0 {
			return int(n), 0
		}
		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, e
		}
		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingRecvMMsgUntilStopped(efd int, fd int, msgHdrs []MMsgHdr) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall6(unix.SYS_RECVMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
		if e == 0 {
			return int(n), e
		}

		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, e
		}

		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingPollUntilStopped(efd int, fd int, events int16) (bool, unix.Errno) {
	pevents := [...]PollEvent{
		{
			FD:     int32(efd),
			Events: unix.POLLIN,
		},
		{
			FD:     int32(fd),
			Events: events,
		},
	}
	_, _, errno := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(&pevents[0])), uintptr(len(pevents)), 0, 0, 0, 0)
	if errno != 0 {
		return pevents[0].Revents&unix.POLLIN != 0, errno
	}

	if pevents[1].Revents&unix.POLLHUP != 0 || pevents[1].Revents&unix.POLLERR != 0 {
		errno = unix.ECONNRESET
	}

	return pevents[0].Revents&unix.POLLIN != 0, errno
}
