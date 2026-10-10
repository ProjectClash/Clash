// Copyright 2021 The gVisor Authors.
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

package header

import "encoding/binary"

const (
	_VIRTIO_NET_HDR_F_NEEDS_CSUM = 1
	_VIRTIO_NET_HDR_GSO_NONE     = 0
	_VIRTIO_NET_HDR_GSO_TCPV4    = 1
	_VIRTIO_NET_HDR_GSO_TCPV6    = 4
)

const (
	VirtioNetHeaderSize = 10
)

const (
	flags      = 0
	gsoType    = 1
	hdrLen     = 2
	gsoSize    = 4
	csumStart  = 6
	csumOffset = 8
)

type VirtioNetHeaderFields struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CSumStart  uint16
	CSumOffset uint16
}

type VirtioNetHeader []byte

func (v VirtioNetHeader) Flags() uint8 {
	return uint8(v[flags])
}

func (v VirtioNetHeader) GSOType() uint8 {
	return uint8(v[gsoType])
}

func (v VirtioNetHeader) HdrLen() uint16 {
	return binary.BigEndian.Uint16(v[hdrLen:])
}

func (v VirtioNetHeader) GSOSize() uint16 {
	return binary.BigEndian.Uint16(v[gsoSize:])
}

func (v VirtioNetHeader) CSumStart() uint16 {
	return binary.BigEndian.Uint16(v[csumStart:])
}

func (v VirtioNetHeader) CSumOffset() uint16 {
	return binary.BigEndian.Uint16(v[csumOffset:])
}

func (v VirtioNetHeader) Encode(f *VirtioNetHeaderFields) {
	v[flags] = uint8(f.Flags)
	v[gsoType] = uint8(f.GSOType)
	binary.LittleEndian.PutUint16(v[hdrLen:], f.HdrLen)
	binary.LittleEndian.PutUint16(v[gsoSize:], f.GSOSize)
	binary.LittleEndian.PutUint16(v[csumStart:], f.CSumStart)
	binary.LittleEndian.PutUint16(v[csumOffset:], f.CSumOffset)
}
