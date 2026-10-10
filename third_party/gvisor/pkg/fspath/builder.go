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

package fspath

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/gohacks"
)

type Builder struct {
	buf     []byte
	start   int
	needSep bool
}

func (b *Builder) Reset() {
	b.start = len(b.buf)
	b.needSep = false
}

func (b *Builder) Len() int {
	return len(b.buf) - b.start
}

func (b *Builder) needToGrow(n int) bool {
	return b.start < n
}

func (b *Builder) grow(n int) {
	newLen := b.Len() + n
	var newCap int
	if len(b.buf) == 0 {
		newCap = 64
	} else {
		newCap = 2 * len(b.buf)
	}
	for newCap < newLen {
		newCap *= 2
		if newCap == 0 {
			panic(fmt.Sprintf("required length (%d) causes buffer size to overflow", newLen))
		}
	}
	newBuf := make([]byte, newCap)
	copy(newBuf[newCap-b.Len():], b.buf[b.start:])
	b.start += newCap - len(b.buf)
	b.buf = newBuf
}

func (b *Builder) PrependComponent(pc string) {
	if b.needSep {
		b.PrependByte('/')
	}
	b.PrependString(pc)
	b.needSep = true
}

func (b *Builder) PrependString(str string) {
	if b.needToGrow(len(str)) {
		b.grow(len(str))
	}
	b.start -= len(str)
	copy(b.buf[b.start:], str)
}

func (b *Builder) PrependByte(c byte) {
	if b.needToGrow(1) {
		b.grow(1)
	}
	b.start--
	b.buf[b.start] = c
}

func (b *Builder) AppendString(str string) {
	if b.needToGrow(len(str)) {
		b.grow(len(str))
	}
	oldStart := b.start
	b.start -= len(str)
	copy(b.buf[b.start:], b.buf[oldStart:])
	copy(b.buf[len(b.buf)-len(str):], str)
}

func (b *Builder) String() string {
	return gohacks.StringFromImmutableBytes(b.buf[b.start:])
}
