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

package header

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	MLDMinimumSize = 20

	MLDHopLimit = 1

	mldMaximumResponseDelayOffset = 0

	mldMulticastAddressOffset = 4
)

type MLD []byte

func (m MLD) MaximumResponseDelay() time.Duration {
	return time.Duration(binary.BigEndian.Uint16(m[mldMaximumResponseDelayOffset:])) * time.Millisecond
}

func (m MLD) SetMaximumResponseDelay(maxRespDelayMS uint16) {
	binary.BigEndian.PutUint16(m[mldMaximumResponseDelayOffset:], maxRespDelayMS)
}

func (m MLD) MulticastAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(m[mldMulticastAddressOffset:][:IPv6AddressSize]))
}

func (m MLD) SetMulticastAddress(multicastAddress tcpip.Address) {
	if n := copy(m[mldMulticastAddressOffset:], multicastAddress.AsSlice()); n != IPv6AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected to copy %d bytes", n, IPv6AddressSize))
	}
}
