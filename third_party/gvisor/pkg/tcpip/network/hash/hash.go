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

package hash

import (
	"encoding/binary"

	"github.com/metacubex/gvisor/pkg/rand"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

var hashIV = RandN32(1)[0]

func RandN32(n int) []uint32 {
	b := make([]byte, 4*n)
	if _, err := rand.Read(b); err != nil {
		panic("unable to get random numbers: " + err.Error())
	}
	r := make([]uint32, n)
	for i := range r {
		r[i] = binary.LittleEndian.Uint32(b[4*i : (4*i + 4)])
	}
	return r
}

func Hash3Words(a, b, c, initval uint32) uint32 {
	const iv = 0xdeadbeef + (3 << 2)
	initval += iv

	a += initval
	b += initval
	c += initval

	c ^= b
	c -= rol32(b, 14)
	a ^= c
	a -= rol32(c, 11)
	b ^= a
	b -= rol32(a, 25)
	c ^= b
	c -= rol32(b, 16)
	a ^= c
	a -= rol32(c, 4)
	b ^= a
	b -= rol32(a, 14)
	c ^= b
	c -= rol32(b, 24)

	return c
}

func IPv4FragmentHash(h header.IPv4) uint32 {
	x := uint32(h.ID())<<16 | uint32(h.Protocol())
	t := h.SourceAddress().As4()
	y := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = h.DestinationAddress().As4()
	z := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return Hash3Words(x, y, z, hashIV)
}

func IPv6FragmentHash(h header.IPv6, id uint32) uint32 {
	t := h.SourceAddress().As16()
	y := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = h.DestinationAddress().As16()
	z := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return Hash3Words(id, y, z, hashIV)
}

func rol32(v, shift uint32) uint32 {
	return (v << shift) | (v >> ((-shift) & 31))
}
