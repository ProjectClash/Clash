// Copyright 2021 The gVisor Authors.
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

package eventfd

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/hostarch"
	"github.com/metacubex/gvisor/pkg/rawfile"
	"github.com/metacubex/gvisor/pkg/safecopy"
)

const sizeofUint64 = 8

type Eventfd struct {
	fd       int
	mmioAddr uintptr
	mmioCtrl MMIOController
}

func Create() (Eventfd, error) {
	fd, _, err := unix.RawSyscall(unix.SYS_EVENTFD2, 0, 0, 0)
	if err != 0 {
		return Eventfd{}, fmt.Errorf("failed to create eventfd: %v", error(err))
	}
	if err := unix.SetNonblock(int(fd), true); err != nil {
		unix.Close(int(fd))
		return Eventfd{}, err
	}
	return Eventfd{fd: int(fd)}, nil
}

func Wrap(fd int) Eventfd {
	return Eventfd{fd: fd}
}

func (ev Eventfd) Close() error {
	if ev.mmioCtrl != nil {
		ev.mmioCtrl.Close(ev)
	}
	return unix.Close(ev.fd)
}

func (ev Eventfd) Dup() (Eventfd, error) {
	other, err := unix.Dup(ev.fd)
	if err != nil {
		return Eventfd{}, fmt.Errorf("failed to dup: %v", other)
	}
	return Eventfd{fd: other}, nil
}

func (ev Eventfd) Notify() error {
	return ev.Write(1)
}

func (ev Eventfd) Write(val uint64) error {
	var buf [sizeofUint64]byte
	hostarch.ByteOrder.PutUint64(buf[:], val)
	if ev.mmioAddr != 0 && ev.mmioCtrl.Enabled() {
		if _, err := safecopy.CopyOut(ev.mmioPtr(), buf[:]); err == nil {
			return nil
		}
	}
	for {
		n, err := nonBlockingWrite(ev.fd, buf[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != sizeofUint64 {
			panic(fmt.Sprintf("bad write to eventfd: got %d bytes, wanted %d with error %v", n, sizeofUint64, err))
		}
		return err
	}
}

func (ev Eventfd) MMIOWrite(val uint64) error {
	var buf [sizeofUint64]byte
	hostarch.ByteOrder.PutUint64(buf[:], val)
	if ev.mmioAddr == 0 {
		return fmt.Errorf("no MMIO address set")
	}
	if !ev.mmioCtrl.Enabled() {
		return fmt.Errorf("MMIO is temporarily disabled")
	}
	_, err := safecopy.CopyOut(ev.mmioPtr(), buf[:])
	return err
}

func (ev Eventfd) Wait() error {
	_, err := ev.Read()
	return err
}

func (ev Eventfd) Read() (uint64, error) {
	var tmp [sizeofUint64]byte
	n, errno := rawfile.BlockingRead(ev.fd, tmp[:])
	if errno != 0 {
		return 0, errno
	}
	if n == 0 {
		return 0, io.EOF
	}
	if n != sizeofUint64 {
		panic(fmt.Sprintf("short read from eventfd: got %d bytes, wanted %d", n, sizeofUint64))
	}
	return hostarch.ByteOrder.Uint64(tmp[:]), nil
}

func (ev Eventfd) FD() int {
	return ev.fd
}

type MMIOController interface {
	Enabled() bool

	Close(ev Eventfd)
}

func (ev *Eventfd) EnableMMIO(addr uintptr, ctrl MMIOController) {
	ev.mmioAddr = addr
	ev.mmioCtrl = ctrl
}

func (ev *Eventfd) DisableMMIO() {
	ev.mmioAddr = 0
	ev.mmioCtrl = nil
}

func (ev Eventfd) MMIOAddr() uintptr {
	return ev.mmioAddr
}
