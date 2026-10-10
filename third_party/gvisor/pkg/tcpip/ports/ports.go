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

package ports

import (
	"math"

	"github.com/metacubex/gvisor/pkg/rand"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

const (
	firstEphemeral = 16000
)

var (
	anyIPAddress = tcpip.Address{}
)

type Reservation struct {
	Networks []tcpip.NetworkProtocolNumber

	Transport tcpip.TransportProtocolNumber

	Addr tcpip.Address

	Port uint16

	Flags Flags

	BindToDevice tcpip.NICID

	Dest tcpip.FullAddress
}

func (rs Reservation) dst() destination {
	return destination{
		rs.Dest.Addr,
		rs.Dest.Port,
	}
}

type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

type destination struct {
	addr tcpip.Address
	port uint16
}

type destToCounter map[destination]FlagCounter

func (dc destToCounter) intersectionFlags(res Reservation) (BitFlags, int) {
	intersection := FlagMask
	var count int

	for dest, counter := range dc {
		if dest == res.dst() {
			intersection &= counter.SharedFlags()
			count++
			continue
		}
		if dest.addr == anyIPAddress || res.Dest.Addr == anyIPAddress {
			intersection &= (^TupleOnlyFlag) | counter.SharedFlags()
			count++
		}
	}

	return intersection, count
}

type deviceToDest map[tcpip.NICID]destToCounter

func (dd deviceToDest) isAvailable(res Reservation, portSpecified bool) bool {
	flagBits := res.Flags.Bits()
	if res.BindToDevice == 0 {
		intersection := FlagMask
		for _, dest := range dd {
			flags, count := dest.intersectionFlags(res)
			if count == 0 {
				continue
			}
			intersection &= flags
			if intersection&flagBits == 0 {
				return false
			}
		}
		if !portSpecified && res.Transport == header.TCPProtocolNumber {
			return false
		}
		return true
	}

	intersection := FlagMask

	if dests, ok := dd[0]; ok {
		var count int
		intersection, count = dests.intersectionFlags(res)
		if count > 0 {
			if intersection&flagBits == 0 {
				return false
			}
			if !portSpecified && res.Transport == header.TCPProtocolNumber {
				return false
			}
		}
	}

	if dests, ok := dd[res.BindToDevice]; ok {
		flags, count := dests.intersectionFlags(res)
		intersection &= flags
		if count > 0 {
			if intersection&flagBits == 0 {
				return false
			}
			if !portSpecified && res.Transport == header.TCPProtocolNumber {
				return false
			}
		}
	}

	return true
}

type addrToDevice map[tcpip.Address]deviceToDest

func (ad addrToDevice) isAvailable(res Reservation, portSpecified bool) bool {
	if res.Addr == anyIPAddress {
		for _, devices := range ad {
			if !devices.isAvailable(res, portSpecified) {
				return false
			}
		}
		return true
	}

	if devices, ok := ad[anyIPAddress]; ok {
		if !devices.isAvailable(res, portSpecified) {
			return false
		}
	}

	if devices, ok := ad[res.Addr]; ok {
		if !devices.isAvailable(res, portSpecified) {
			return false
		}
	}

	return true
}

type PortManager struct {
	mu sync.RWMutex `state:"nosave"`
	allocatedPorts map[portDescriptor]addrToDevice

	ephemeralMu    sync.RWMutex `state:"nosave"`
	firstEphemeral uint16
	numEphemeral   uint16
}

func NewPortManager() *PortManager {
	return &PortManager{
		allocatedPorts: make(map[portDescriptor]addrToDevice),
		firstEphemeral: firstEphemeral,
		numEphemeral:   math.MaxUint16 - firstEphemeral + 1,
	}
}

type PortTester func(port uint16) (good bool, err tcpip.Error)

func (pm *PortManager) PickEphemeralPort(rng rand.RNG, testPort PortTester) (port uint16, err tcpip.Error) {
	pm.ephemeralMu.RLock()
	firstEphemeral := pm.firstEphemeral
	numEphemeral := pm.numEphemeral
	pm.ephemeralMu.RUnlock()

	return pickEphemeralPort(rng.Uint32(), firstEphemeral, numEphemeral, testPort)
}

func pickEphemeralPort(offset uint32, first, count uint16, testPort PortTester) (port uint16, err tcpip.Error) {
	for i := uint32(0); i < uint32(count); i++ {
		port := uint16(uint32(first) + (offset+i)%uint32(count))
		ok, err := testPort(port)
		if err != nil {
			return 0, err
		}

		if ok {
			return port, nil
		}
	}

	return 0, &tcpip.ErrNoPortAvailable{}
}

func (pm *PortManager) ReservePort(rng rand.RNG, res Reservation, testPort PortTester) (reservedPort uint16, err tcpip.Error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if res.Port != 0 {
		if !pm.reserveSpecificPortLocked(res, true) {
			return 0, &tcpip.ErrPortInUse{}
		}
		if testPort != nil {
			ok, err := testPort(res.Port)
			if err != nil {
				pm.releasePortLocked(res)
				return 0, err
			}
			if !ok {
				pm.releasePortLocked(res)
				return 0, &tcpip.ErrPortInUse{}
			}
		}
		return res.Port, nil
	}

	return pm.PickEphemeralPort(rng, func(p uint16) (bool, tcpip.Error) {
		res.Port = p
		if !pm.reserveSpecificPortLocked(res, false) {
			return false, nil
		}
		if testPort != nil {
			ok, err := testPort(p)
			if err != nil {
				pm.releasePortLocked(res)
				return false, err
			}
			if !ok {
				pm.releasePortLocked(res)
				return false, nil
			}
		}
		return true, nil
	})
}

func (pm *PortManager) reserveSpecificPortLocked(res Reservation, portSpecified bool) bool {
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		if addrs, ok := pm.allocatedPorts[desc]; ok {
			if !addrs.isAvailable(res, portSpecified) {
				return false
			}
		}
	}

	flagBits := res.Flags.Bits()
	dst := res.dst()
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		addrToDev, ok := pm.allocatedPorts[desc]
		if !ok {
			addrToDev = make(addrToDevice)
			pm.allocatedPorts[desc] = addrToDev
		}
		devToDest, ok := addrToDev[res.Addr]
		if !ok {
			devToDest = make(deviceToDest)
			addrToDev[res.Addr] = devToDest
		}
		destToCntr := devToDest[res.BindToDevice]
		if destToCntr == nil {
			destToCntr = make(destToCounter)
		}
		counter := destToCntr[dst]
		counter.AddRef(flagBits)
		destToCntr[dst] = counter
		devToDest[res.BindToDevice] = destToCntr
	}

	return true
}

func (pm *PortManager) ReserveTuple(res Reservation) bool {
	flagBits := res.Flags.Bits()
	dst := res.dst()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	undo := false

	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		addrToDev, ok := pm.allocatedPorts[desc]
		if !ok {
			addrToDev = make(addrToDevice)
			pm.allocatedPorts[desc] = addrToDev
		}
		devToDest, ok := addrToDev[res.Addr]
		if !ok {
			devToDest = make(deviceToDest)
			addrToDev[res.Addr] = devToDest
		}
		destToCntr := devToDest[res.BindToDevice]
		if destToCntr == nil {
			destToCntr = make(destToCounter)
		}

		counter := destToCntr[dst]
		if counter.TotalRefs() != 0 && counter.SharedFlags()&flagBits == 0 {
			undo = true
		}
		counter.AddRef(flagBits)
		destToCntr[dst] = counter
		devToDest[res.BindToDevice] = destToCntr
	}

	if undo {
		pm.releasePortLocked(res)
		return false
	}

	return true
}

func (pm *PortManager) ReleasePort(res Reservation) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.releasePortLocked(res)
}

func (pm *PortManager) releasePortLocked(res Reservation) {
	dst := res.dst()
	for _, network := range res.Networks {
		desc := portDescriptor{network, res.Transport, res.Port}
		addrToDev, ok := pm.allocatedPorts[desc]
		if !ok {
			continue
		}
		devToDest, ok := addrToDev[res.Addr]
		if !ok {
			continue
		}
		destToCounter, ok := devToDest[res.BindToDevice]
		if !ok {
			continue
		}
		counter, ok := destToCounter[dst]
		if !ok {
			continue
		}
		counter.DropRef(res.Flags.Bits())
		if counter.TotalRefs() > 0 {
			destToCounter[dst] = counter
			continue
		}
		delete(destToCounter, dst)
		if len(destToCounter) > 0 {
			continue
		}
		delete(devToDest, res.BindToDevice)
		if len(devToDest) > 0 {
			continue
		}
		delete(addrToDev, res.Addr)
		if len(addrToDev) > 0 {
			continue
		}
		delete(pm.allocatedPorts, desc)
	}
}

func (pm *PortManager) PortRange() (uint16, uint16) {
	pm.ephemeralMu.RLock()
	defer pm.ephemeralMu.RUnlock()
	return pm.firstEphemeral, pm.firstEphemeral + pm.numEphemeral - 1
}

func (pm *PortManager) SetPortRange(start uint16, end uint16) tcpip.Error {
	if start > end {
		return &tcpip.ErrInvalidPortRange{}
	}
	pm.ephemeralMu.Lock()
	defer pm.ephemeralMu.Unlock()
	pm.firstEphemeral = start
	pm.numEphemeral = end - start + 1
	return nil
}
