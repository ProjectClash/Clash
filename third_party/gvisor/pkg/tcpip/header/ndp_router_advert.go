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

import (
	"encoding/binary"
	"fmt"
	"time"
)

var _ fmt.Stringer = NDPRoutePreference(0)

type NDPRoutePreference uint8

const (
	HighRoutePreference NDPRoutePreference = 0b01

	MediumRoutePreference = 0b00

	LowRoutePreference = 0b11

	ReservedRoutePreference = 0b10
)

func (p NDPRoutePreference) String() string {
	switch p {
	case HighRoutePreference:
		return "HighRoutePreference"
	case MediumRoutePreference:
		return "MediumRoutePreference"
	case LowRoutePreference:
		return "LowRoutePreference"
	case ReservedRoutePreference:
		return "ReservedRoutePreference"
	default:
		return fmt.Sprintf("NDPRoutePreference(%d)", p)
	}
}

type NDPRouterAdvert []byte

const (
	NDPRAMinimumSize = 12

	ndpRACurrHopLimitOffset = 0

	ndpRAFlagsOffset = 1

	ndpRAManagedAddrConfFlagMask = (1 << 7)

	ndpRAOtherConfFlagMask = (1 << 6)

	ndpDefaultRouterPreferenceShift = 3

	ndpDefaultRouterPreferenceMask = (0b11 << ndpDefaultRouterPreferenceShift)

	ndpRARouterLifetimeOffset = 2

	ndpRAReachableTimeOffset = 4

	ndpRARetransTimerOffset = 8

	ndpRAOptionsOffset = 12
)

func (b NDPRouterAdvert) CurrHopLimit() uint8 {
	return b[ndpRACurrHopLimitOffset]
}

func (b NDPRouterAdvert) ManagedAddrConfFlag() bool {
	return b[ndpRAFlagsOffset]&ndpRAManagedAddrConfFlagMask != 0
}

func (b NDPRouterAdvert) OtherConfFlag() bool {
	return b[ndpRAFlagsOffset]&ndpRAOtherConfFlagMask != 0
}

func (b NDPRouterAdvert) DefaultRouterPreference() NDPRoutePreference {
	return NDPRoutePreference((b[ndpRAFlagsOffset] & ndpDefaultRouterPreferenceMask) >> ndpDefaultRouterPreferenceShift)
}

func (b NDPRouterAdvert) RouterLifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint16(b[ndpRARouterLifetimeOffset:]))
}

func (b NDPRouterAdvert) ReachableTime() time.Duration {
	return time.Millisecond * time.Duration(binary.BigEndian.Uint32(b[ndpRAReachableTimeOffset:]))
}

func (b NDPRouterAdvert) RetransTimer() time.Duration {
	return time.Millisecond * time.Duration(binary.BigEndian.Uint32(b[ndpRARetransTimerOffset:]))
}

func (b NDPRouterAdvert) Options() NDPOptions {
	return NDPOptions(b[ndpRAOptionsOffset:])
}
