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

	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
)

type Buffer struct {
	data ViewList `state:".([]byte)"`
	size int64
}

func (b *Buffer) removeView(v *View) {
	b.data.Remove(v)
	v.Release()
}

func MakeWithData(b []byte) Buffer {
	buf := Buffer{}
	if len(b) == 0 {
		return buf
	}
	v := NewViewWithData(b)
	buf.Append(v)
	return buf
}

func MakeWithView(v *View) Buffer {
	if v == nil {
		return Buffer{}
	}
	b := Buffer{
		size: int64(v.Size()),
	}
	if b.size == 0 {
		v.Release()
		return b
	}
	b.data.PushBack(v)
	return b
}

func (b *Buffer) Release() {
	for v := b.data.Front(); v != nil; v = b.data.Front() {
		b.removeView(v)
	}
	b.size = 0
}

func (b *Buffer) TrimFront(count int64) {
	if count >= b.size {
		b.advanceRead(b.size)
	} else {
		b.advanceRead(count)
	}
}

func (b *Buffer) ReadAt(p []byte, offset int64) (int, error) {
	var (
		skipped int64
		done    int64
	)
	for v := b.data.Front(); v != nil && done < int64(len(p)); v = v.Next() {
		needToSkip := int(offset - skipped)
		if sz := v.Size(); sz <= needToSkip {
			skipped += int64(sz)
			continue
		}

		n := copy(p[done:], v.AsSlice()[needToSkip:])
		skipped += int64(needToSkip)
		done += int64(n)
	}
	if int(done) < len(p) || offset+done == b.size {
		return int(done), io.EOF
	}
	return int(done), nil
}

func (b *Buffer) advanceRead(count int64) {
	for v := b.data.Front(); v != nil && count > 0; {
		sz := int64(v.Size())
		if sz > count {
			v.TrimFront(int(count))
			b.size -= count
			count = 0
			return
		}

		oldView := v
		v = v.Next()
		b.removeView(oldView)

		count -= sz
		b.size -= sz
	}
	if count > 0 {
		panic(fmt.Sprintf("advanceRead still has %d bytes remaining", count))
	}
}

func (b *Buffer) Truncate(length int64) {
	if length < 0 {
		panic("negative length provided")
	}
	if length >= b.size {
		return
	}
	for v := b.data.Back(); v != nil && b.size > length; v = b.data.Back() {
		sz := int64(v.Size())
		if after := b.size - sz; after < length {
			left := (length - after)
			v.write = v.read + int(left)
			b.size = length
			break
		}

		b.removeView(v)
		b.size -= sz
	}
}

func (b *Buffer) GrowTo(length int64, zero bool) {
	if length < 0 {
		panic("negative length provided")
	}
	for b.size < length {
		v := b.data.Back()

		if v.Full() {
			v = NewView(int(length - b.size))
			b.data.PushBack(v)
		}

		sz := v.AvailableSize()
		if int64(sz) > length-b.size {
			sz = int(length - b.size)
		}

		if zero {
			common.ClearArray(v.chunk.data[v.write : v.write+sz])
		}

		v.Grow(sz)
		b.size += int64(sz)
	}
}

func (b *Buffer) Prepend(src *View) error {
	if src == nil {
		return nil
	}
	if src.Size() == 0 {
		src.Release()
		return nil
	}
	v := b.data.Front()
	if v == nil || v.read == 0 {
		b.prependOwned(src)
		return nil
	}

	if !v.sharesChunk() {
		avail := v.read
		vStart := 0
		srcStart := src.Size() - avail
		if avail > src.Size() {
			vStart = avail - src.Size()
			srcStart = 0
		}
		old := v.write
		v.read = vStart
		n, err := v.WriteAt(src.AsSlice()[srcStart:], 0)
		if err != nil {
			return fmt.Errorf("could not write to view during append: %w", err)
		}
		b.size += int64(n)
		v.write = old
		src.write = srcStart

		if src.Size() == 0 {
			src.Release()
			return nil
		}
	}

	b.prependOwned(src)
	return nil
}

func (b *Buffer) Append(src *View) error {
	if src == nil {
		return nil
	}
	if src.Size() == 0 {
		src.Release()
		return nil
	}
	v := b.data.Back()
	if v.Full() {
		b.appendOwned(src)
		return nil
	}

	if !v.sharesChunk() {
		writeSz := src.Size()
		if src.Size() > v.AvailableSize() {
			writeSz = v.AvailableSize()
		}
		done, err := v.Write(src.AsSlice()[:writeSz])
		if err != nil {
			return fmt.Errorf("could not write to view during append: %w", err)
		}
		src.TrimFront(done)
		b.size += int64(done)
		if src.Size() == 0 {
			src.Release()
			return nil
		}
	}

	b.appendOwned(src)
	return nil
}

func (b *Buffer) appendOwned(v *View) {
	b.data.PushBack(v)
	b.size += int64(v.Size())
}

func (b *Buffer) prependOwned(v *View) {
	b.data.PushFront(v)
	b.size += int64(v.Size())
}

func (b *Buffer) PullUp(offset, length int) (View, bool) {
	if length == 0 {
		return View{}, true
	}
	tgt := Range{begin: offset, end: offset + length}
	if tgt.Intersect(Range{end: int(b.size)}).Len() != length {
		return View{}, false
	}

	curr := Range{}
	v := b.data.Front()
	for ; v != nil; v = v.Next() {
		origLen := v.Size()
		curr.end = curr.begin + origLen

		if x := curr.Intersect(tgt); x.Len() == tgt.Len() {
			sub := x.Offset(-curr.begin)
			if v.sharesChunk() {
				old := v.chunk
				v.chunk = v.chunk.Clone()
				old.DecRef()
			}
			new := View{
				read:  v.read + sub.begin,
				write: v.read + sub.end,
				chunk: v.chunk,
			}
			return new, true
		} else if x.Len() > 0 {
			break
		}

		curr.begin += origLen
	}

	totLen := 0
	for n := v; n != nil; n = n.Next() {
		totLen += n.Size()
		if curr.begin+totLen >= tgt.end {
			break
		}
	}

	merged := NewViewSize(totLen)
	off := 0
	for n := v; n != nil && off < totLen; {
		merged.WriteAt(n.AsSlice(), off)
		off += n.Size()

		if n == v {
			n = n.Next()
		} else {
			old := n
			n = n.Next()
			b.removeView(old)
		}
	}
	b.data.InsertBefore(v, merged)
	b.removeView(v)

	r := tgt.Offset(-curr.begin)
	pulled := View{
		read:  r.begin,
		write: r.end,
		chunk: merged.chunk,
	}
	return pulled, true
}

func (b *Buffer) Flatten() []byte {
	if v := b.data.Front(); v == nil {
		return nil
	}
	data := make([]byte, 0, b.size)
	for v := b.data.Front(); v != nil; v = v.Next() {
		data = append(data, v.AsSlice()...)
	}
	return data
}

func (b *Buffer) Size() int64 {
	return b.size
}

func (b *Buffer) AsViewList() ViewList {
	return b.data
}

func (b *Buffer) Clone() Buffer {
	other := Buffer{
		size: b.size,
	}
	for v := b.data.Front(); v != nil; v = v.Next() {
		newView := v.Clone()
		other.data.PushBack(newView)
	}
	return other
}

func (b *Buffer) DeepClone() Buffer {
	newBuf := Buffer{}
	buf := b.Clone()
	reader := buf.AsBufferReader()
	newBuf.WriteFromReader(&reader, b.size)
	return newBuf
}

func (b *Buffer) Apply(fn func(*View)) {
	for v := b.data.Front(); v != nil; v = v.Next() {
		d := v.Clone()
		fn(d)
		d.Release()
	}
}

func (b *Buffer) SubApply(offset, length int, fn func(*View)) {
	for v := b.data.Front(); length > 0 && v != nil; v = v.Next() {
		if offset >= v.Size() {
			offset -= v.Size()
			continue
		}
		d := v.Clone()
		if offset > 0 {
			d.TrimFront(offset)
			offset = 0
		}
		if length < d.Size() {
			d.write = d.read + length
		}
		fn(d)
		length -= d.Size()
		d.Release()
	}
}

func (b *Buffer) Checksum(offset int) uint16 {
	if offset >= int(b.size) {
		return 0
	}
	var v *View
	for v = b.data.Front(); v != nil && offset >= v.Size(); v = v.Next() {
		offset -= v.Size()
	}

	var cs checksum.Checksumer
	cs.Add(v.AsSlice()[offset:])
	for v = v.Next(); v != nil; v = v.Next() {
		cs.Add(v.AsSlice())
	}
	return cs.Checksum()
}

func (b *Buffer) Merge(other *Buffer) {
	b.data.PushBackList(&other.data)
	other.data = ViewList{}

	b.size += other.size
	other.size = 0
}

func (b *Buffer) WriteFromReader(r io.Reader, count int64) (int64, error) {
	return b.WriteFromReaderAndLimitedReader(r, count, nil)
}

func (b *Buffer) WriteFromReaderAndLimitedReader(r io.Reader, count int64, lr *io.LimitedReader) (int64, error) {
	if lr == nil {
		lr = &io.LimitedReader{}
	}

	var done int64
	for done < count {
		vsize := count - done
		if vsize > MaxChunkSize {
			vsize = MaxChunkSize
		}
		v := NewView(int(vsize))
		lr.R = r
		lr.N = vsize
		n, err := io.Copy(v, lr)
		b.Append(v)
		done += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (b *Buffer) ReadToWriter(w io.Writer, count int64) (int64, error) {
	bytesLeft := int(count)
	for v := b.data.Front(); v != nil && bytesLeft > 0; v = v.Next() {
		view := v.Clone()
		if view.Size() > bytesLeft {
			view.CapLength(bytesLeft)
		}
		n, err := io.Copy(w, view)
		bytesLeft -= int(n)
		view.Release()
		if err != nil {
			return count - int64(bytesLeft), err
		}
	}
	return count - int64(bytesLeft), nil
}

func (b *Buffer) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.Size() == 0 {
		return 0, io.EOF
	}
	done := 0
	v := b.data.Front()
	for v != nil && done < len(p) {
		n, err := v.Read(p[done:])
		done += n
		next := v.Next()
		if v.Size() == 0 {
			b.removeView(v)
		}
		b.size -= int64(n)
		if err != nil && err != io.EOF {
			return done, err
		}
		v = next
	}
	return done, nil
}

func (b *Buffer) readByte() (byte, error) {
	if b.Size() == 0 {
		return 0, io.EOF
	}
	v := b.data.Front()
	bt := v.AsSlice()[0]
	b.TrimFront(1)
	return bt, nil
}

func (b *Buffer) AsBufferReader() BufferReader {
	return BufferReader{b}
}

type BufferReader struct {
	b *Buffer
}

func (br *BufferReader) Read(p []byte) (int, error) {
	return br.b.read(p)
}

func (br *BufferReader) ReadByte() (byte, error) {
	return br.b.readByte()
}

func (br *BufferReader) Close() {
	br.b.Release()
}

func (br *BufferReader) Len() int {
	return int(br.b.Size())
}

type Range struct {
	begin int
	end   int
}

func (x Range) Intersect(y Range) Range {
	if x.begin < y.begin {
		x.begin = y.begin
	}
	if x.end > y.end {
		x.end = y.end
	}
	if x.begin >= x.end {
		return Range{}
	}
	return x
}

func (x Range) Offset(off int) Range {
	x.begin += off
	x.end += off
	return x
}

func (x Range) Len() int {
	l := x.end - x.begin
	if l < 0 {
		l = 0
	}
	return l
}
