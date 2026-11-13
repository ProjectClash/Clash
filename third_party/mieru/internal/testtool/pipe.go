// Copyright (C) 2022  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package testtool

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enfein/mieru/v3/pkg/common"
)

func BufPipe() (net.Conn, net.Conn) {
	var buf1, buf2 bytes.Buffer
	var lock1, lock2 sync.Mutex
	cond1 := sync.NewCond(&lock1)
	cond2 := sync.NewCond(&lock2)

	ep1 := &ioEndpoint{
		direction: forward,
		buf1:      &buf1,
		buf2:      &buf2,
		lock1:     &lock1,
		lock2:     &lock2,
		cond1:     cond1,
		cond2:     cond2,
	}
	ep2 := &ioEndpoint{
		direction: backward,
		buf1:      &buf1,
		buf2:      &buf2,
		lock1:     &lock1,
		lock2:     &lock2,
		cond1:     cond1,
		cond2:     cond2,
	}
	ep1.peer = ep2
	ep2.peer = ep1
	return ep1, ep2
}

type ioDirection int

const (
	forward ioDirection = iota
	backward
)

type ioEndpoint struct {
	direction     ioDirection
	buf1          *bytes.Buffer
	buf2          *bytes.Buffer
	lock1         *sync.Mutex
	lock2         *sync.Mutex
	cond1         *sync.Cond
	cond2         *sync.Cond
	closed        atomic.Bool
	peer          *ioEndpoint
	readDeadline  deadline
	writeDeadline time.Time
}

var _ net.Conn = &ioEndpoint{}

func (e *ioEndpoint) Read(b []byte) (n int, err error) {
	buffer, lock, cond := e.readSide()
	lock.Lock()
	defer lock.Unlock()

	for {
		if e.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		if e.readDeadline.exceeded {
			return 0, os.ErrDeadlineExceeded
		}
		if buffer.Len() > 0 {
			return buffer.Read(b)
		}
		if e.peer.closed.Load() {
			return 0, io.EOF
		}
		cond.Wait()
	}
}

func (e *ioEndpoint) Write(b []byte) (n int, err error) {
	buffer, lock, cond := e.writeSide()
	lock.Lock()
	defer lock.Unlock()

	if e.closed.Load() || e.peer.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if !e.writeDeadline.IsZero() && !time.Now().Before(e.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}

	n, err = buffer.Write(b)
	cond.Broadcast()
	return
}

func (e *ioEndpoint) Close() error {
	if e.closed.Swap(true) {
		return nil
	}
	for _, cond := range []*sync.Cond{e.cond1, e.cond2} {
		cond.L.Lock()
		cond.Broadcast()
		cond.L.Unlock()
	}
	return nil
}

func (e *ioEndpoint) LocalAddr() net.Addr {
	return common.NilNetAddr()
}

func (e *ioEndpoint) RemoteAddr() net.Addr {
	return common.NilNetAddr()
}

func (e *ioEndpoint) SetDeadline(t time.Time) error {
	if err := e.SetReadDeadline(t); err != nil {
		return err
	}
	return e.SetWriteDeadline(t)
}

func (e *ioEndpoint) SetReadDeadline(t time.Time) error {
	_, lock, cond := e.readSide()
	lock.Lock()
	defer lock.Unlock()

	if e.closed.Load() {
		return io.ErrClosedPipe
	}
	e.readDeadline.set(t, cond)
	return nil
}

func (e *ioEndpoint) SetWriteDeadline(t time.Time) error {
	_, lock, _ := e.writeSide()
	lock.Lock()
	defer lock.Unlock()

	if e.closed.Load() {
		return io.ErrClosedPipe
	}
	e.writeDeadline = t
	return nil
}

func (e *ioEndpoint) readSide() (*bytes.Buffer, *sync.Mutex, *sync.Cond) {
	if e.direction == forward {
		return e.buf2, e.lock2, e.cond2
	}
	return e.buf1, e.lock1, e.cond1
}

func (e *ioEndpoint) writeSide() (*bytes.Buffer, *sync.Mutex, *sync.Cond) {
	if e.direction == forward {
		return e.buf1, e.lock1, e.cond1
	}
	return e.buf2, e.lock2, e.cond2
}

type deadline struct {
	timer    *time.Timer
	seq      uint64
	exceeded bool
}

func (d *deadline) set(t time.Time, cond *sync.Cond) {
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.seq++
	d.exceeded = false
	if t.IsZero() {
		return
	}

	if dur := time.Until(t); dur > 0 {
		seq := d.seq
		d.timer = time.AfterFunc(dur, func() {
			cond.L.Lock()
			defer cond.L.Unlock()
			if d.seq == seq {
				d.exceeded = true
				cond.Broadcast()
			}
		})
		return
	}
	d.exceeded = true
	cond.Broadcast()
}
