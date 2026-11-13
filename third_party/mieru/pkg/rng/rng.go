// Copyright (C) 2021  mieru authors
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

package rng

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	mrand "math/rand"
	"os"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/version"
)

var fixed sync.Map
var fixedV sync.Map

func Intn(n int) int {
	return int(float64(mrand.Intn(n+1)) * scaleDown())
}

func Int63n(n int64) int64 {
	return int64(float64(mrand.Int63n(n+1)) * scaleDown())
}

func IntRange(m, n int) int {
	return m + Intn(n-m)
}

func IntRange64(m, n int64) int64 {
	return m + Int63n(n-m)
}

func RandTime(begin, end time.Time) time.Time {
	beginNano := begin.UnixNano()
	endNano := end.UnixNano()
	randNano := IntRange64(beginNano, endNano)
	randSec := randNano / 1000000000
	randNano = randNano % 1000000000
	return time.Unix(randSec, randNano)
}

func Uint32WithBits(n int) uint32 {
	if n < 0 || n > 32 {
		panic("number of set bits must be between 0 and 32")
	}

	var bitPositions [32]uint32
	for i := range bitPositions {
		bitPositions[i] = uint32(i)
	}

	var result uint32
	for i := 0; i < n; i++ {
		j := i + mrand.Intn(len(bitPositions)-i)
		bitPositions[i], bitPositions[j] = bitPositions[j], bitPositions[i]
		result |= uint32(1) << bitPositions[i]
	}
	return result
}

func FixedInt(n int, hint string) int {
	if n <= 0 {
		return 0
	}
	v, ok := fixed.Load(hint)
	if !ok {
		b := sha256.Sum256([]byte(hint))
		b[0] = b[0] & 0b01111111
		v = int(binary.BigEndian.Uint32(b[:4]))
		fixed.Store(hint, v)
	}
	return v.(int) % n
}

func FixedIntV(n int, hint string) int {
	if n <= 0 {
		return 0
	}
	v, ok := fixedV.Load(hint)
	if !ok {
		seed := hint + " " + version.AppVersion
		b := sha256.Sum256([]byte(seed))
		b[0] = b[0] & 0b01111111
		v = int(binary.BigEndian.Uint32(b[:4]))
		fixedV.Store(hint, v)
	}
	return v.(int) % n
}

func FixedIntVH(n int) int {
	hostName, _ := os.Hostname()
	return FixedIntV(n, hostName)
}

func scaleDown() float64 {
	base := mrand.Float64()
	return math.Sqrt(base * base * base)
}
