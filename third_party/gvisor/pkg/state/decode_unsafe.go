// Copyright 2020 The gVisor Authors.
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

package state

import (
	"fmt"
	"reflect"
	"runtime"
	"unsafe"
)

func reflectValueRWAddr(obj reflect.Value) reflect.Value {
	return reflect.NewAt(obj.Type(), unsafe.Pointer(obj.UnsafeAddr()))
}

func reflectValueRWSlice3(arr reflect.Value, i, j, k int) reflect.Value {
	if arr.Kind() != reflect.Array {
		panic(fmt.Sprintf("arr has kind %v, wanted %v", arr.Kind(), reflect.Array))
	}
	if i < 0 || j < 0 || k < 0 {
		panic(fmt.Sprintf("negative subscripts (%d, %d, %d)", i, j, k))
	}
	if i > j {
		panic(fmt.Sprintf("subscript i (%d) > j (%d)", i, j))
	}
	if j > k {
		panic(fmt.Sprintf("subscript j (%d) > k (%d)", j, k))
	}
	if k > arr.Len() {
		panic(fmt.Sprintf("subscript k (%d) > array length (%d)", k, arr.Len()))
	}

	sliceTyp := reflect.SliceOf(arr.Type().Elem())
	if i == arr.Len() {
		return reflect.MakeSlice(sliceTyp, 0, 0)
	}
	slh := reflect.SliceHeader{
		Data: arr.Index(i).UnsafeAddr(),
		Len:  j - i,
		Cap:  k - i,
	}
	slobj := reflect.NewAt(sliceTyp, unsafe.Pointer(&slh)).Elem()
	runtime.KeepAlive(arr)
	return slobj
}
