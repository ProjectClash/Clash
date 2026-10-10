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

package header

import (
	"encoding/binary"
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
)

func PseudoHeaderChecksum(protocol tcpip.TransportProtocolNumber, srcAddr tcpip.Address, dstAddr tcpip.Address, totalLen uint16) uint16 {
	xsum := checksum.Checksum(srcAddr.AsSlice(), 0)
	xsum = checksum.Checksum(dstAddr.AsSlice(), xsum)

	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], totalLen)
	xsum = checksum.Checksum(tmp[:], xsum)

	return checksum.Checksum([]byte{0, uint8(protocol)}, xsum)
}

func checksumUpdate2ByteAlignedUint16(xsum, old, new uint16) uint16 {
	if old == new {
		return xsum
	}
	return checksum.Combine(xsum, checksum.Combine(new, ^old))
}

func checksumUpdate2ByteAlignedAddress(xsum uint16, old, new tcpip.Address) uint16 {
	const uint16Bytes = 2

	if old.BitLen() != new.BitLen() {
		panic(fmt.Sprintf("buffer lengths are different; old = %d, new = %d", old.BitLen()/8, new.BitLen()/8))
	}

	if oldBytes := old.BitLen() % 16; oldBytes != 0 {
		panic(fmt.Sprintf("buffer has an odd number of bytes; got = %d", oldBytes))
	}

	oldAddr := old.AsSlice()
	newAddr := new.AsSlice()

	for len(oldAddr) != 0 {
		xsum = checksumUpdate2ByteAlignedUint16(xsum, (uint16(oldAddr[0])<<8)+uint16(oldAddr[1]), (uint16(newAddr[0])<<8)+uint16(newAddr[1]))
		oldAddr = oldAddr[uint16Bytes:]
		newAddr = newAddr[uint16Bytes:]
	}

	return xsum
}
