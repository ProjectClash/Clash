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

package jenkins

import (
	"hash"
)

type Sum32 uint32

func New32() hash.Hash32 {
	var s Sum32
	return &s
}

func (s *Sum32) Reset() { *s = 0 }

func (s *Sum32) Sum32() uint32 {
	sCopy := *s

	sCopy += sCopy << 3
	sCopy ^= sCopy >> 11
	sCopy += sCopy << 15

	return uint32(sCopy)
}

func (s *Sum32) Write(data []byte) (int, error) {
	sCopy := *s
	for _, b := range data {
		sCopy += Sum32(b)
		sCopy += sCopy << 10
		sCopy ^= sCopy >> 6
	}
	*s = sCopy
	return len(data), nil
}

func (s *Sum32) Size() int { return 4 }

func (s *Sum32) BlockSize() int { return 1 }

func (s *Sum32) Sum(in []byte) []byte {
	v := s.Sum32()
	return append(in, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
