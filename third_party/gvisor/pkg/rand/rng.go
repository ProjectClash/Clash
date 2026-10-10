// Copyright 2023 The gVisor Authors.
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

package rand

import (
	"encoding/binary"
	"fmt"
	"io"
)

type RNG struct {
	Reader io.Reader
}

func RNGFrom(r io.Reader) RNG {
	return RNG{Reader: r}
}

func (rg *RNG) Uint16() uint16 {
	var data [2]byte
	if _, err := rg.Reader.Read(data[:]); err != nil {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	return binary.LittleEndian.Uint16(data[:])
}

func (rg *RNG) Uint32() uint32 {
	var data [4]byte
	if _, err := rg.Reader.Read(data[:]); err != nil {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	return binary.LittleEndian.Uint32(data[:])
}

func (rg *RNG) Int63n(n int64) int64 {
	if n <= 0 {
		panic(fmt.Sprintf("n must be positive, but got %d", n))
	}

	if n&(n-1) == 0 {
		return int64(rg.Uint64()) & (n - 1)
	}

	maximum := int64((1 << 63) - 1 - (1<<63)%uint64(n))
	ret := rg.Int63()
	for ret > maximum {
		ret = rg.Int63()
	}
	return ret % n
}

func (rg *RNG) Int63() int64 {
	return ((1 << 63) - 1) & int64(rg.Uint64())
}

func (rg *RNG) Uint64() uint64 {
	var data [8]byte
	if _, err := rg.Reader.Read(data[:]); err != nil {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	return binary.LittleEndian.Uint64(data[:])
}

func Uint32() uint32 {
	rng := RNG{Reader: Reader}
	return rng.Uint32()
}

func Int63n(n int64) int64 {
	rng := RNG{Reader: Reader}
	return rng.Int63n(n)
}

func Int63() int64 {
	rng := RNG{Reader: Reader}
	return rng.Int63()
}

func Uint64() uint64 {
	rng := RNG{Reader: Reader}
	return rng.Uint64()
}
