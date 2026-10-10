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

package unet

import (
	"io"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (s *Socket) wait(write bool) error {
	for {
		fd := s.fd.Load()
		if fd < 0 {
			return errClosing
		}

		events := []unix.PollFd{
			{
				Fd:     fd,
				Events: unix.POLLIN,
			},
			{
				Fd:     int32(s.efd.FD()),
				Events: unix.POLLIN,
			},
		}
		if write {
			events[0].Events = unix.POLLOUT
		}

		_, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(&events[0])), 2, 0, 0, 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			return e
		}

		if events[1].Revents&unix.POLLIN == unix.POLLIN {
			return errClosing
		}

		return nil
	}
}

func buildIovec(bufs [][]byte, iovecs []unix.Iovec) ([]unix.Iovec, int) {
	var length int
	for i := range bufs {
		if l := len(bufs[i]); l > 0 {
			iovecs = append(iovecs, unix.Iovec{
				Base: &bufs[i][0],
				Len:  uint64(l),
			})
			length += l
		}
	}
	return iovecs, length
}

func (r *SocketReader) ReadVec(bufs [][]byte) (int, error) {
	iovecs, length := buildIovec(bufs, make([]unix.Iovec, 0, 2))

	var msg unix.Msghdr
	if len(r.source) != 0 {
		msg.Name = &r.source[0]
		msg.Namelen = uint32(len(r.source))
	}

	if len(r.ControlMessage) != 0 {
		msg.Control = &r.ControlMessage[0]
		msg.Controllen = uint64(len(r.ControlMessage))
	}

	if len(iovecs) != 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}

	var n uintptr

	fd, ok := r.socket.enterFD()
	if !ok {
		return 0, unix.EBADF
	}
	for {
		var e unix.Errno

		n, _, e = unix.RawSyscall(unix.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), unix.MSG_DONTWAIT|unix.MSG_TRUNC)
		if e == 0 {
			break
		}
		if e == unix.EINTR {
			continue
		}
		if !r.blocking {
			r.socket.gate.Leave()
			return 0, e
		}
		if e != unix.EAGAIN && e != unix.EWOULDBLOCK {
			r.socket.gate.Leave()
			return 0, e
		}

		err := r.socket.wait(false)
		if err == errClosing {
			err = unix.EBADF
		}
		if err != nil {
			r.socket.gate.Leave()
			return 0, err
		}
	}

	r.socket.gate.Leave()

	if msg.Controllen < uint64(len(r.ControlMessage)) {
		r.ControlMessage = r.ControlMessage[:msg.Controllen]
	}

	if msg.Namelen < uint32(len(r.source)) {
		r.source = r.source[:msg.Namelen]
	}

	if n == 0 {
		return 0, io.EOF
	}

	if r.race != nil {
		r.race.Add(1)
	}

	if int(n) > length {
		return length, errMessageTruncated
	}

	return int(n), nil
}

func (w *SocketWriter) WriteVec(bufs [][]byte) (int, error) {
	iovecs, _ := buildIovec(bufs, make([]unix.Iovec, 0, 2))

	if w.race != nil {
		w.race.Add(1)
	}

	var msg unix.Msghdr
	if len(w.to) != 0 {
		msg.Name = &w.to[0]
		msg.Namelen = uint32(len(w.to))
	}

	if len(w.ControlMessage) != 0 {
		msg.Control = &w.ControlMessage[0]
		msg.Controllen = uint64(len(w.ControlMessage))
	}

	if len(iovecs) > 0 {
		msg.Iov = &iovecs[0]
		msg.Iovlen = uint64(len(iovecs))
	}

	fd, ok := w.socket.enterFD()
	if !ok {
		return 0, unix.EBADF
	}
	for {
		n, _, e := unix.RawSyscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		if e == 0 {
			w.socket.gate.Leave()
			return int(n), nil
		}
		if e == unix.EINTR {
			continue
		}
		if !w.blocking {
			w.socket.gate.Leave()
			return 0, e
		}
		if e != unix.EAGAIN && e != unix.EWOULDBLOCK {
			w.socket.gate.Leave()
			return 0, e
		}

		err := w.socket.wait(true)
		if err == errClosing {
			err = unix.EBADF
		}
		if err != nil {
			w.socket.gate.Leave()
			return 0, err
		}
	}
}

func getsockopt(fd int, level int, optname int, buf []byte) (uint32, error) {
	l := uint32(len(buf))
	_, _, e := unix.RawSyscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 {
		return 0, e
	}

	return l, nil
}

func setsockopt(fd int, level int, optname int, buf []byte) error {
	_, _, e := unix.RawSyscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if e != 0 {
		return e
	}

	return nil
}

func getsockname(fd int, buf []byte) (uint32, error) {
	l := uint32(len(buf))
	_, _, e := unix.RawSyscall(unix.SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)))
	if e != 0 {
		return 0, e
	}

	return l, nil
}

func getpeername(fd int, buf []byte) (uint32, error) {
	l := uint32(len(buf))
	_, _, e := unix.RawSyscall(unix.SYS_GETPEERNAME, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)))
	if e != 0 {
		return 0, e
	}

	return l, nil
}
