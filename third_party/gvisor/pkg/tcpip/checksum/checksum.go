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

package checksum

import (
	"encoding/binary"
)

const Size = 2

func Put(b []byte, xsum uint16) {
	binary.BigEndian.PutUint16(b, xsum)
}

func Checksum(buf []byte, initial uint16) uint16 {
	s, _ := calculateChecksum(buf, false, initial)
	return s
}

type Checksumer struct {
	sum uint16
	odd bool
}

func (c *Checksumer) Add(b []byte) {
	if len(b) > 0 {
		c.sum, c.odd = calculateChecksum(b, c.odd, c.sum)
	}
}

func (c *Checksumer) Checksum() uint16 {
	return c.sum
}

func Combine(a, b uint16) uint16 {
	v := uint32(a) + uint32(b)
	return uint16(v + v>>16)
}
