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

//go:build amd64 || 386
// +build amd64 386

package hostarch

import "encoding/binary"

const (
	PageSize = 1 << PageShift

	HugePageSize = 1 << HugePageShift

	JumboPageSize = 1 << JumboPageShift

	CacheLineSize = 1 << CacheLineShift

	PageShift = 12

	HugePageShift = 21

	JumboPageShift = 30

	CacheLineShift = 6
)

var (
	ByteOrder = binary.LittleEndian
)

func UntaggedUserAddr(addr Addr) Addr {
	return addr
}
