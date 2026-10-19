// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"errors"
	"fmt"
	"sync"
)

var dataChunkPools = [...]sync.Pool{
	{New: func() interface{} { return new([1 << 10]byte) }},
	{New: func() interface{} { return new([2 << 10]byte) }},
	{New: func() interface{} { return new([4 << 10]byte) }},
	{New: func() interface{} { return new([8 << 10]byte) }},
	{New: func() interface{} { return new([16 << 10]byte) }},
}

func getDataBufferChunk(size int64) []byte {
	switch {
	case size <= 1<<10:
		return dataChunkPools[0].Get().(*[1 << 10]byte)[:]
	case size <= 2<<10:
		return dataChunkPools[1].Get().(*[2 << 10]byte)[:]
	case size <= 4<<10:
		return dataChunkPools[2].Get().(*[4 << 10]byte)[:]
	case size <= 8<<10:
		return dataChunkPools[3].Get().(*[8 << 10]byte)[:]
	default:
		return dataChunkPools[4].Get().(*[16 << 10]byte)[:]
	}
}

func putDataBufferChunk(p []byte) {
	switch len(p) {
	case 1 << 10:
		dataChunkPools[0].Put((*[1 << 10]byte)(p))
	case 2 << 10:
		dataChunkPools[1].Put((*[2 << 10]byte)(p))
	case 4 << 10:
		dataChunkPools[2].Put((*[4 << 10]byte)(p))
	case 8 << 10:
		dataChunkPools[3].Put((*[8 << 10]byte)(p))
	case 16 << 10:
		dataChunkPools[4].Put((*[16 << 10]byte)(p))
	default:
		panic(fmt.Sprintf("unexpected buffer len=%v", len(p)))
	}
}

type dataBuffer struct {
	chunks   [][]byte
	r        int
	w        int
	size     int
	expected int64
}

var errReadEmpty = errors.New("read from empty dataBuffer")

func (b *dataBuffer) Read(p []byte) (int, error) {
	if b.size == 0 {
		return 0, errReadEmpty
	}
	var ntotal int
	for len(p) > 0 && b.size > 0 {
		readFrom := b.bytesFromFirstChunk()
		n := copy(p, readFrom)
		p = p[n:]
		ntotal += n
		b.r += n
		b.size -= n
		if b.r == len(b.chunks[0]) {
			putDataBufferChunk(b.chunks[0])
			end := len(b.chunks) - 1
			copy(b.chunks[:end], b.chunks[1:])
			b.chunks[end] = nil
			b.chunks = b.chunks[:end]
			b.r = 0
		}
	}
	return ntotal, nil
}

func (b *dataBuffer) bytesFromFirstChunk() []byte {
	if len(b.chunks) == 1 {
		return b.chunks[0][b.r:b.w]
	}
	return b.chunks[0][b.r:]
}

func (b *dataBuffer) Len() int {
	return b.size
}

func (b *dataBuffer) Write(p []byte) (int, error) {
	ntotal := len(p)
	for len(p) > 0 {
		want := int64(len(p))
		if b.expected > want {
			want = b.expected
		}
		chunk := b.lastChunkOrAlloc(want)
		n := copy(chunk[b.w:], p)
		p = p[n:]
		b.w += n
		b.size += n
		b.expected -= int64(n)
	}
	return ntotal, nil
}

func (b *dataBuffer) lastChunkOrAlloc(want int64) []byte {
	if len(b.chunks) != 0 {
		last := b.chunks[len(b.chunks)-1]
		if b.w < len(last) {
			return last
		}
	}
	chunk := getDataBufferChunk(want)
	b.chunks = append(b.chunks, chunk)
	b.w = 0
	return chunk
}
