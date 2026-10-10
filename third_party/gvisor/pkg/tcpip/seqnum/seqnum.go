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

package seqnum

type Value uint32

type Size uint32

func (v Value) LessThan(w Value) bool {
	return int32(v-w) < 0
}

func (v Value) LessThanEq(w Value) bool {
	if v == w {
		return true
	}
	return v.LessThan(w)
}

func (v Value) InRange(a, b Value) bool {
	return v-a < b-a
}

func (v Value) InWindow(first Value, size Size) bool {
	return v.InRange(first, first.Add(size))
}

func (v Value) Add(s Size) Value {
	return v + Value(s)
}

func (v Value) Size(w Value) Size {
	return Size(w - v)
}

func (v *Value) UpdateForward(s Size) {
	*v += Value(s)
}
