// Copyright 2022 The gVisor Authors.
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

package buffer

import (
	"fmt"
	"io"

	"github.com/metacubex/gvisor/pkg/sync"
)

const ReadSize = 512

var viewPool = sync.Pool{
	New: func() any {
		return &View{}
	},
}

type View struct {
	ViewEntry `state:"nosave"`
	read      int
	write     int
	chunk     *chunk
}

func NewView(cap int) *View {
	c := newChunk(cap)
	v := viewPool.Get().(*View)
	*v = View{chunk: c}
	return v
}

func NewViewSize(size int) *View {
	v := NewView(size)
	v.Grow(size)
	return v
}

func NewViewWithData(data []byte) *View {
	c := newChunk(len(data))
	v := viewPool.Get().(*View)
	*v = View{chunk: c}
	v.Write(data)
	return v
}

func (v *View) Clone() *View {
	if v == nil {
		panic("cannot clone a nil view")
	}
	v.chunk.IncRef()
	newV := viewPool.Get().(*View)
	newV.chunk = v.chunk
	newV.read = v.read
	newV.write = v.write
	return newV
}

func (v *View) Release() {
	if v == nil {
		panic("cannot release a nil view")
	}
	v.chunk.DecRef()
	*v = View{}
	viewPool.Put(v)
}

func (v *View) Reset() {
	if v == nil {
		panic("cannot reset a nil view")
	}
	v.read = 0
	v.write = 0
}

func (v *View) sharesChunk() bool {
	return v.chunk.refCount.Load() > 1
}

func (v *View) Full() bool {
	return v == nil || v.write == len(v.chunk.data)
}

func (v *View) Capacity() int {
	if v == nil {
		return 0
	}
	return len(v.chunk.data)
}

func (v *View) Size() int {
	if v == nil {
		return 0
	}
	return v.write - v.read
}

func (v *View) TrimFront(n int) {
	if v.read+n > v.write {
		panic("cannot trim past the end of a view")
	}
	v.read += n
}

func (v *View) AsSlice() []byte {
	if v.Size() == 0 {
		return nil
	}
	return v.chunk.data[v.read:v.write]
}

func (v *View) ToSlice() []byte {
	if v.Size() == 0 {
		return nil
	}
	s := make([]byte, v.Size())
	copy(s, v.AsSlice())
	return s
}

func (v *View) AvailableSize() int {
	if v == nil {
		return 0
	}
	return len(v.chunk.data) - v.write
}

func (v *View) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if v.Size() == 0 {
		return 0, io.EOF
	}
	n := copy(p, v.AsSlice())
	v.TrimFront(n)
	return n, nil
}

func (v *View) ReadByte() (byte, error) {
	if v.Size() == 0 {
		return 0, io.EOF
	}
	b := v.AsSlice()[0]
	v.read++
	return b, nil
}

func (v *View) WriteTo(w io.Writer) (n int64, err error) {
	if v.Size() > 0 {
		sz := v.Size()
		m, e := w.Write(v.AsSlice())
		v.TrimFront(m)
		n = int64(m)
		if e != nil {
			return n, e
		}
		if m != sz {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func (v *View) ReadAt(p []byte, off int) (int, error) {
	if off < 0 || off > v.Size() {
		return 0, fmt.Errorf("ReadAt(): offset out of bounds: want 0 < off < %d, got off=%d", v.Size(), off)
	}
	n := copy(p, v.AsSlice()[off:])
	return n, nil
}

func (v *View) Write(p []byte) (int, error) {
	if v == nil {
		panic("cannot write to a nil view")
	}
	if v.AvailableSize() < len(p) {
		v.growCap(len(p) - v.AvailableSize())
	} else if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	n := copy(v.chunk.data[v.write:], p)
	v.write += n
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (v *View) ReadFrom(r io.Reader) (n int64, err error) {
	if v == nil {
		panic("cannot write to a nil view")
	}
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	for {
		if _, e := r.Read(nil); e == io.EOF {
			return n, nil
		}
		if v.AvailableSize() == 0 {
			v.growCap(ReadSize)
		}
		m, e := r.Read(v.availableSlice())
		v.write += m
		n += int64(m)

		if e == io.EOF {
			return n, nil
		}
		if e != nil {
			return n, e
		}
	}
}

func (v *View) WriteAt(p []byte, off int) (int, error) {
	if v == nil {
		panic("cannot write to a nil view")
	}
	if off < 0 || off > v.Size() {
		return 0, fmt.Errorf("write offset out of bounds: want 0 < off < %d, got off=%d", v.Size(), off)
	}
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		v.chunk = v.chunk.Clone()
	}
	n := copy(v.AsSlice()[off:], p)
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (v *View) Grow(n int) {
	if v == nil {
		panic("cannot grow a nil view")
	}
	if v.write+n > v.Capacity() {
		v.growCap(n)
	}
	v.write += n
}

func (v *View) growCap(n int) {
	if v == nil {
		panic("cannot grow a nil view")
	}
	defer v.chunk.DecRef()
	old := v.AsSlice()
	v.chunk = newChunk(v.Capacity() + n)
	copy(v.chunk.data, old)
	v.read = 0
	v.write = len(old)
}

func (v *View) CapLength(n int) {
	if v == nil {
		panic("cannot resize a nil view")
	}
	if n < 0 {
		panic("n must be >= 0")
	}
	if n > v.Size() {
		n = v.Size()
	}
	v.write = v.read + n
}

func (v *View) availableSlice() []byte {
	if v.sharesChunk() {
		defer v.chunk.DecRef()
		c := v.chunk.Clone()
		v.chunk = c
	}
	return v.chunk.data[v.write:]
}
