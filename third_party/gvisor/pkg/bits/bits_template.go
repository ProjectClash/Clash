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

package bits

import "github.com/metacubex/gvisor/pkg/common/x/constraints"


func IsOn[T constraints.Integer](mask, bits T) bool {
	return mask&bits == bits
}

func IsAnyOn[T constraints.Integer](mask, bits T) bool {
	return mask&bits != 0
}

func Mask[T constraints.Integer](is ...int) T {
	ret := T(0)
	for _, i := range is {
		ret |= MaskOf[T](i)
	}
	return ret
}

func MaskOf[T constraints.Integer](i int) T {
	return T(1) << T(i)
}

func IsPowerOfTwo[T constraints.Integer](v T) bool {
	if v == 0 {
		return false
	}
	return v&(v-1) == 0
}
