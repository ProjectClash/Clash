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

package header

import "github.com/metacubex/gvisor/pkg/tcpip"

type NDPNeighborSolicit []byte

const (
	NDPNSMinimumSize = 20

	ndpNSTargetAddessOffset = 4

	ndpNSOptionsOffset = ndpNSTargetAddessOffset + IPv6AddressSize
)

func (b NDPNeighborSolicit) TargetAddress() tcpip.Address {
	return tcpip.AddrFrom16Slice(b[ndpNSTargetAddessOffset:][:IPv6AddressSize])
}

func (b NDPNeighborSolicit) SetTargetAddress(addr tcpip.Address) {
	copy(b[ndpNSTargetAddessOffset:][:IPv6AddressSize], addr.AsSlice())
}

func (b NDPNeighborSolicit) Options() NDPOptions {
	return NDPOptions(b[ndpNSOptionsOffset:])
}
