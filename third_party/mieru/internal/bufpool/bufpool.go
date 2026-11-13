// Copyright (C) 2026  mieru authors
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

package bufpool

import "sync"

var classes = [...]struct {
	size int
	pool sync.Pool
}{
	{size: 256},
	{size: 2 * 1024},
	{size: 8*1024 + 1024},
	{size: 32*1024 + 1024},
	{size: 64*1024 + 1024},
}

type Buffer struct {
	storage []byte
	size    int
	pool    *sync.Pool
}

func Acquire(size int) *Buffer {
	if size < 0 {
		panic("bufpool: negative size")
	}
	for i := range classes {
		class := &classes[i]
		if size > class.size {
			continue
		}
		if cached := class.pool.Get(); cached != nil {
			buf := cached.(*Buffer)
			buf.size = size
			return buf
		}
		return &Buffer{storage: make([]byte, class.size), size: size, pool: &class.pool}
	}
	return &Buffer{storage: make([]byte, size), size: size}
}

func (b *Buffer) Bytes() []byte {
	return b.storage[:b.size:b.size]
}

func (b *Buffer) Release() {
	b.size = 0
	if b.pool != nil {
		b.pool.Put(b)
	} else {
		b.storage = nil
	}
}
