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

package tun

import (
	"encoding/binary"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	PacketInfoHeaderSize = 4

	offsetFlags    = 0
	offsetProtocol = 2
)

type PacketInfoFields struct {
	Flags    uint16
	Protocol tcpip.NetworkProtocolNumber
}

type PacketInfoHeader []byte

func (h PacketInfoHeader) Encode(f *PacketInfoFields) {
	binary.BigEndian.PutUint16(h[offsetFlags:][:2], f.Flags)
	binary.BigEndian.PutUint16(h[offsetProtocol:][:2], uint16(f.Protocol))
}

func (h PacketInfoHeader) Flags() uint16 {
	return binary.BigEndian.Uint16(h[offsetFlags:])
}

func (h PacketInfoHeader) Protocol() tcpip.NetworkProtocolNumber {
	return tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(h[offsetProtocol:]))
}
