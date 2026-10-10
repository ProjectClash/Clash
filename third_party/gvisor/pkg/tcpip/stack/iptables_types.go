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

package stack

import (
	"fmt"
	"strings"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

type Hook uint

const (
	Prerouting Hook = iota

	Input

	Forward

	Output

	Postrouting

	NumHooks
)

type RuleVerdict int

const (
	RuleAccept RuleVerdict = iota

	RuleDrop

	RuleJump

	RuleReturn
)

type IPTables struct {
	connections ConnTrack

	reaper tcpip.Timer `state:"nosave"`

	mu ipTablesRWMutex `state:"nosave"`
	v4Tables [NumTables]Table
	v6Tables [NumTables]Table
	modified bool
}

func (it *IPTables) Modified() bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.modified
}

func (it *IPTables) VisitTargets(transform func(Target) Target) {
	it.mu.Lock()
	defer it.mu.Unlock()

	for tid := range it.v4Tables {
		for i, rule := range it.v4Tables[tid].Rules {
			it.v4Tables[tid].Rules[i].Target = transform(rule.Target)
		}
	}
	for tid := range it.v6Tables {
		for i, rule := range it.v6Tables[tid].Rules {
			it.v6Tables[tid].Rules[i].Target = transform(rule.Target)
		}
	}
}

type Table struct {
	Rules []Rule

	BuiltinChains [NumHooks]int

	Underflows [NumHooks]int
}

func (table *Table) ValidHooks() uint32 {
	hooks := uint32(0)
	for hook, ruleIdx := range table.BuiltinChains {
		if ruleIdx != HookUnset {
			hooks |= 1 << hook
		}
	}
	return hooks
}

type Rule struct {
	Filter IPHeaderFilter

	Matchers []Matcher

	Target Target
}

type IPHeaderFilter struct {
	Protocol tcpip.TransportProtocolNumber

	CheckProtocol bool

	Dst tcpip.Address

	DstMask tcpip.Address

	DstInvert bool

	Src tcpip.Address

	SrcMask tcpip.Address

	SrcInvert bool

	InputInterface string

	InputInterfaceMask string

	InputInterfaceInvert bool

	OutputInterface string

	OutputInterfaceMask string

	OutputInterfaceInvert bool
}

func EmptyFilter4() IPHeaderFilter {
	return IPHeaderFilter{
		Dst:     tcpip.AddrFrom4([4]byte{}),
		DstMask: tcpip.AddrFrom4([4]byte{}),
		Src:     tcpip.AddrFrom4([4]byte{}),
		SrcMask: tcpip.AddrFrom4([4]byte{}),
	}
}

func EmptyFilter6() IPHeaderFilter {
	return IPHeaderFilter{
		Dst:     tcpip.AddrFrom16([16]byte{}),
		DstMask: tcpip.AddrFrom16([16]byte{}),
		Src:     tcpip.AddrFrom16([16]byte{}),
		SrcMask: tcpip.AddrFrom16([16]byte{}),
	}
}

func (fl IPHeaderFilter) match(pkt *PacketBuffer, hook Hook, inNicName, outNicName string) bool {
	var (
		transProto tcpip.TransportProtocolNumber
		dstAddr    tcpip.Address
		srcAddr    tcpip.Address
	)
	switch proto := pkt.NetworkProtocolNumber; proto {
	case header.IPv4ProtocolNumber:
		hdr := header.IPv4(pkt.NetworkHeader().Slice())
		transProto = hdr.TransportProtocol()
		dstAddr = hdr.DestinationAddress()
		srcAddr = hdr.SourceAddress()

	case header.IPv6ProtocolNumber:
		hdr := header.IPv6(pkt.NetworkHeader().Slice())
		transProto = pkt.TransportProtocolNumber
		dstAddr = hdr.DestinationAddress()
		srcAddr = hdr.SourceAddress()

	default:
		panic(fmt.Sprintf("unknown network protocol with EtherType: %d", proto))
	}

	if fl.CheckProtocol && fl.Protocol != transProto {
		return false
	}

	if !filterAddress(dstAddr, fl.DstMask, fl.Dst, fl.DstInvert) ||
		!filterAddress(srcAddr, fl.SrcMask, fl.Src, fl.SrcInvert) {
		return false
	}

	switch hook {
	case Prerouting, Input:
		return matchIfName(inNicName, fl.InputInterface, fl.InputInterfaceInvert)
	case Postrouting, Output:
		return matchIfName(outNicName, fl.OutputInterface, fl.OutputInterfaceInvert)
	case Forward:
		if !matchIfName(inNicName, fl.InputInterface, fl.InputInterfaceInvert) {
			return false
		}

		if !matchIfName(outNicName, fl.OutputInterface, fl.OutputInterfaceInvert) {
			return false
		}

		return true
	default:
		panic(fmt.Sprintf("unknown hook: %d", hook))
	}
}

func matchIfName(nicName string, ifName string, invert bool) bool {
	n := len(ifName)
	if n == 0 {
		return true
	}
	var matches bool
	if strings.HasSuffix(ifName, "+") {
		matches = strings.HasPrefix(nicName, ifName[:n-1])
	} else {
		matches = nicName == ifName
	}
	return matches != invert
}

func (fl IPHeaderFilter) NetworkProtocol() tcpip.NetworkProtocolNumber {
	switch fl.Src.BitLen() {
	case header.IPv4AddressSizeBits:
		return header.IPv4ProtocolNumber
	case header.IPv6AddressSizeBits:
		return header.IPv6ProtocolNumber
	}
	panic(fmt.Sprintf("invalid address in IPHeaderFilter: %s", fl.Src))
}

func filterAddress(addr, mask, filterAddr tcpip.Address, invert bool) bool {
	matches := true
	addrBytes := addr.AsSlice()
	maskBytes := mask.AsSlice()
	filterBytes := filterAddr.AsSlice()
	for i := range filterAddr.AsSlice() {
		if addrBytes[i]&maskBytes[i] != filterBytes[i] {
			matches = false
			break
		}
	}
	return matches != invert
}

type Matcher interface {
	Match(hook Hook, packet *PacketBuffer, inputInterfaceName, outputInterfaceName string) (matches bool, hotdrop bool)
}

type Target interface {
	Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int)
}
