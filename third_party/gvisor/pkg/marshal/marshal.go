// Copyright 2019 The gVisor Authors.
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

package marshal

import (
	"io"

	"github.com/metacubex/gvisor/pkg/hostarch"
)

type CopyContext interface {
	CopyScratchBuffer(size int) []byte

	CopyOutBytes(addr hostarch.Addr, b []byte) (int, error)

	CopyInBytes(addr hostarch.Addr, b []byte) (int, error)
}

type Marshallable interface {
	io.WriterTo

	SizeBytes() int

	MarshalBytes(dst []byte) []byte

	UnmarshalBytes(src []byte) []byte

	Packed() bool

	MarshalUnsafe(dst []byte) []byte

	UnmarshalUnsafe(src []byte) []byte

	CopyIn(cc CopyContext, addr hostarch.Addr) (int, error)

	CopyInN(cc CopyContext, addr hostarch.Addr, limit int) (int, error)

	CopyOut(cc CopyContext, addr hostarch.Addr) (int, error)

	CopyOutN(cc CopyContext, addr hostarch.Addr, limit int) (int, error)
}

type CheckedMarshallable interface {
	CheckedMarshal(dst []byte) ([]byte, bool)

	CheckedUnmarshal(src []byte) ([]byte, bool)
}

