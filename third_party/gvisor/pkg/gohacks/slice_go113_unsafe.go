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

//go:build go1.13 && !go1.20
// +build go1.13,!go1.20


package gohacks

import (
	"unsafe"
)

type sliceHeader struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

func Slice[T any](ptr *T, length int) []T {
	var s []T
	hdr := (*sliceHeader)(unsafe.Pointer(&s))
	hdr.Data = unsafe.Pointer(ptr)
	hdr.Len = length
	hdr.Cap = length
	return s
}
