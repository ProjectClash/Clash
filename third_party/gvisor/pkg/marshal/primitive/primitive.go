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

package primitive

import (
	"io"

	"github.com/metacubex/gvisor/pkg/hostarch"
	"github.com/metacubex/gvisor/pkg/marshal"
)

type Int8 int8

type Uint8 uint8

type Int16 int16

type Uint16 uint16

type Int32 int32

type Uint32 uint32

type Int64 int64

type Uint64 uint64

type ByteSlice []byte

func (b *ByteSlice) SizeBytes() int {
	return len(*b)
}

func (b *ByteSlice) MarshalBytes(dst []byte) []byte {
	return dst[copy(dst, *b):]
}

func (b *ByteSlice) UnmarshalBytes(src []byte) []byte {
	return src[copy(*b, src):]
}

func (b *ByteSlice) Packed() bool {
	return false
}

func (b *ByteSlice) MarshalUnsafe(dst []byte) []byte {
	return b.MarshalBytes(dst)
}

func (b *ByteSlice) UnmarshalUnsafe(src []byte) []byte {
	return b.UnmarshalBytes(src)
}

func (b *ByteSlice) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
	return cc.CopyInBytes(addr, *b)
}

func (b *ByteSlice) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
	return cc.CopyInBytes(addr, (*b)[:limit])
}

func (b *ByteSlice) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
	return cc.CopyOutBytes(addr, *b)
}

func (b *ByteSlice) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
	return cc.CopyOutBytes(addr, (*b)[:limit])
}

func (b *ByteSlice) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(*b)
	return int64(n), err
}

var _ marshal.Marshallable = (*ByteSlice)(nil)


func AllocateInt8(x int8) marshal.Marshallable {
	p := Int8(x)
	return &p
}

func AllocateUint8(x uint8) marshal.Marshallable {
	p := Uint8(x)
	return &p
}

func AllocateInt16(x int16) marshal.Marshallable {
	p := Int16(x)
	return &p
}

func AllocateUint16(x uint16) marshal.Marshallable {
	p := Uint16(x)
	return &p
}

func AllocateInt32(x int32) marshal.Marshallable {
	p := Int32(x)
	return &p
}

func AllocateUint32(x uint32) marshal.Marshallable {
	p := Uint32(x)
	return &p
}

func AllocateInt64(x int64) marshal.Marshallable {
	p := Int64(x)
	return &p
}

func AllocateUint64(x uint64) marshal.Marshallable {
	p := Uint64(x)
	return &p
}

func AsByteSlice(b []byte) marshal.Marshallable {
	bs := ByteSlice(b)
	return &bs
}



func CopyInt8In(cc marshal.CopyContext, addr hostarch.Addr, dst *int8) (int, error) {
	var buf Int8
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int8(buf)
	return n, nil
}

func CopyInt8Out(cc marshal.CopyContext, addr hostarch.Addr, src int8) (int, error) {
	srcP := Int8(src)
	return srcP.CopyOut(cc, addr)
}

func CopyUint8In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint8) (int, error) {
	var buf Uint8
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint8(buf)
	return n, nil
}

func CopyUint8Out(cc marshal.CopyContext, addr hostarch.Addr, src uint8) (int, error) {
	srcP := Uint8(src)
	return srcP.CopyOut(cc, addr)
}


func CopyInt16In(cc marshal.CopyContext, addr hostarch.Addr, dst *int16) (int, error) {
	var buf Int16
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int16(buf)
	return n, nil
}

func CopyInt16Out(cc marshal.CopyContext, addr hostarch.Addr, src int16) (int, error) {
	srcP := Int16(src)
	return srcP.CopyOut(cc, addr)
}

func CopyUint16In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint16) (int, error) {
	var buf Uint16
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint16(buf)
	return n, nil
}

func CopyUint16Out(cc marshal.CopyContext, addr hostarch.Addr, src uint16) (int, error) {
	srcP := Uint16(src)
	return srcP.CopyOut(cc, addr)
}


func CopyInt32In(cc marshal.CopyContext, addr hostarch.Addr, dst *int32) (int, error) {
	var buf Int32
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int32(buf)
	return n, nil
}

func CopyInt32Out(cc marshal.CopyContext, addr hostarch.Addr, src int32) (int, error) {
	srcP := Int32(src)
	return srcP.CopyOut(cc, addr)
}

func CopyUint32In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint32) (int, error) {
	var buf Uint32
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint32(buf)
	return n, nil
}

func CopyUint32Out(cc marshal.CopyContext, addr hostarch.Addr, src uint32) (int, error) {
	srcP := Uint32(src)
	return srcP.CopyOut(cc, addr)
}


func CopyInt64In(cc marshal.CopyContext, addr hostarch.Addr, dst *int64) (int, error) {
	var buf Int64
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int64(buf)
	return n, nil
}

func CopyInt64Out(cc marshal.CopyContext, addr hostarch.Addr, src int64) (int, error) {
	srcP := Int64(src)
	return srcP.CopyOut(cc, addr)
}

func CopyUint64In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint64) (int, error) {
	var buf Uint64
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint64(buf)
	return n, nil
}

func CopyUint64Out(cc marshal.CopyContext, addr hostarch.Addr, src uint64) (int, error) {
	srcP := Uint64(src)
	return srcP.CopyOut(cc, addr)
}

func CopyByteSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst *[]byte) (int, error) {
	var buf ByteSlice
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = []byte(buf)
	return n, nil
}

func CopyByteSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []byte) (int, error) {
	srcP := ByteSlice(src)
	return srcP.CopyOut(cc, addr)
}

func CopyStringIn(cc marshal.CopyContext, addr hostarch.Addr, dst *string) (int, error) {
	var buf ByteSlice
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = string(buf)
	return n, nil
}

func CopyStringOut(cc marshal.CopyContext, addr hostarch.Addr, src string) (int, error) {
	srcP := ByteSlice(src)
	return srcP.CopyOut(cc, addr)
}
