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

import "github.com/metacubex/sing-tun/internal/gtcpip"

type NDPNeighborAdvert []byte

const (
	NDPNAMinimumSize = 20

	ndpNATargetAddressOffset = 4

	ndpNAOptionsOffset = ndpNATargetAddressOffset + IPv6AddressSize

	ndpNAFlagsOffset = 0

	ndpNARouterFlagMask = (1 << 7)

	ndpNASolicitedFlagMask = (1 << 6)

	ndpNAOverrideFlagMask = (1 << 5)
)

func (b NDPNeighborAdvert) TargetAddress() tcpip.Address {
	return tcpip.AddrFrom16Slice(b[ndpNATargetAddressOffset:][:IPv6AddressSize])
}

func (b NDPNeighborAdvert) SetTargetAddress(addr tcpip.Address) {
	copy(b[ndpNATargetAddressOffset:][:IPv6AddressSize], addr.AsSlice())
}

func (b NDPNeighborAdvert) RouterFlag() bool {
	return b[ndpNAFlagsOffset]&ndpNARouterFlagMask != 0
}

func (b NDPNeighborAdvert) SetRouterFlag(f bool) {
	if f {
		b[ndpNAFlagsOffset] |= ndpNARouterFlagMask
	} else {
		b[ndpNAFlagsOffset] &^= ndpNARouterFlagMask
	}
}

func (b NDPNeighborAdvert) SolicitedFlag() bool {
	return b[ndpNAFlagsOffset]&ndpNASolicitedFlagMask != 0
}

func (b NDPNeighborAdvert) SetSolicitedFlag(f bool) {
	if f {
		b[ndpNAFlagsOffset] |= ndpNASolicitedFlagMask
	} else {
		b[ndpNAFlagsOffset] &^= ndpNASolicitedFlagMask
	}
}

func (b NDPNeighborAdvert) OverrideFlag() bool {
	return b[ndpNAFlagsOffset]&ndpNAOverrideFlagMask != 0
}

func (b NDPNeighborAdvert) SetOverrideFlag(f bool) {
	if f {
		b[ndpNAFlagsOffset] |= ndpNAOverrideFlagMask
	} else {
		b[ndpNAFlagsOffset] &^= ndpNAOverrideFlagMask
	}
}

func (b NDPNeighborAdvert) Options() NDPOptions {
	return NDPOptions(b[ndpNAOptionsOffset:])
}
