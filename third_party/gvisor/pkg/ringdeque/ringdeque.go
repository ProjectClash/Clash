// Copyright 2024 The gVisor Authors.
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

package ringdeque

type Deque[T any] struct {
	off uint64
	len uint64
	buf []T
}

func (d *Deque[T]) expand() {
	newLen := 2
	if d.len != 0 {
		newLen = len(d.buf) * 2
	}
	newBuf := make([]T, newLen)
	n := copy(newBuf, d.buf[d.off:])
	copy(newBuf[n:], d.buf[:d.off])
	d.off = 0
	d.buf = newBuf
}

func (d *Deque[T]) mask() uint64 {
	return uint64(len(d.buf)) - 1
}

func (d *Deque[T]) Empty() bool {
	return d.len == 0
}

func (d *Deque[T]) Len() int {
	return int(d.len)
}

func (d *Deque[T]) Clear() {
	d.len = 0
}

func (d *Deque[T]) PushFront(x T) {
	if int(d.len) == len(d.buf) {
		d.expand()
	}
	newOff := (d.off - 1) & d.mask()
	d.buf[newOff] = x
	d.off = newOff
	d.len++
}

func (d *Deque[T]) PushBack(x T) {
	if int(d.len) == len(d.buf) {
		d.expand()
	}
	i := (d.off + d.len) & d.mask()
	d.buf[i] = x
	d.len++
}

func (d *Deque[T]) PeekFront() T {
	return *d.PeekFrontPtr()
}

func (d *Deque[T]) PeekFrontPtr() *T {
	if d.Empty() {
		panic("peek of empty Deque")
	}
	return &d.buf[d.off]
}

func (d *Deque[T]) PeekBack() T {
	return *d.PeekBackPtr()
}

func (d *Deque[T]) PeekBackPtr() *T {
	if d.Empty() {
		panic("peek of empty Deque")
	}
	i := (d.off + d.len - 1) & d.mask()
	return &d.buf[i]
}

func (d *Deque[T]) RemoveFront() {
	d.off = (d.off + 1) & d.mask()
	d.len--
}

func (d *Deque[T]) RemoveBack() {
	d.len--
}

func (d *Deque[T]) PopFront() (x T) {
	x = d.PeekFront()
	d.RemoveFront()
	return
}

func (d *Deque[T]) PopBack() (x T) {
	x = d.PeekBack()
	d.RemoveBack()
	return
}
