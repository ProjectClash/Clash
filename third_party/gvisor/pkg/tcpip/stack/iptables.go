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
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

type TableID int

const (
	NATID TableID = iota
	MangleID
	FilterID
	RawID
	NumTables
)

const HookUnset = -1

const reaperDelay = 5 * time.Second

func DefaultTables(clock tcpip.Clock, rand *rand.Rand) *IPTables {
	return &IPTables{
		v4Tables: [NumTables]Table{
			NATID: {
				Rules: []Rule{
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			MangleID: {
				Rules: []Rule{
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			FilterID: {
				Rules: []Rule{
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
			RawID: {
				Rules: []Rule{
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
					{Filter: EmptyFilter4(), Target: &ErrorTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
		},
		v6Tables: [NumTables]Table{
			NATID: {
				Rules: []Rule{
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       1,
					Forward:     HookUnset,
					Output:      2,
					Postrouting: 3,
				},
			},
			MangleID: {
				Rules: []Rule{
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting: 0,
					Output:     1,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
			FilterID: {
				Rules: []Rule{
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  HookUnset,
					Input:       0,
					Forward:     1,
					Output:      2,
					Postrouting: HookUnset,
				},
			},
			RawID: {
				Rules: []Rule{
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
					{Filter: EmptyFilter6(), Target: &ErrorTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
				},
				BuiltinChains: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
				Underflows: [NumHooks]int{
					Prerouting:  0,
					Input:       HookUnset,
					Forward:     HookUnset,
					Output:      1,
					Postrouting: HookUnset,
				},
			},
		},
		connections: ConnTrack{
			seed:  rand.Uint32(),
			clock: clock,
			rng:   rand,
		},
	}
}

func EmptyFilterTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
		Underflows: [NumHooks]int{
			Prerouting:  HookUnset,
			Postrouting: HookUnset,
		},
	}
}

func EmptyNATTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Forward: HookUnset,
		},
		Underflows: [NumHooks]int{
			Forward: HookUnset,
		},
	}
}

func EmptyRawTable() Table {
	return Table{
		Rules: []Rule{},
		BuiltinChains: [NumHooks]int{
			Input:       HookUnset,
			Forward:     HookUnset,
			Postrouting: HookUnset,
		},
		Underflows: [NumHooks]int{
			Input:       HookUnset,
			Forward:     HookUnset,
			Postrouting: HookUnset,
		},
	}
}

func (it *IPTables) GetTable(id TableID, ipv6 bool) Table {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.getTableRLocked(id, ipv6)
}

func (it *IPTables) getTableRLocked(id TableID, ipv6 bool) Table {
	if ipv6 {
		return it.v6Tables[id]
	}
	return it.v4Tables[id]
}

func (it *IPTables) ReplaceTable(id TableID, table Table, ipv6 bool) {
	it.replaceTable(id, table, ipv6, false)
}

func (it *IPTables) ForceReplaceTable(id TableID, table Table, ipv6 bool) {
	it.replaceTable(id, table, ipv6, true)
}

func (it *IPTables) replaceTable(id TableID, table Table, ipv6, force bool) {
	it.mu.Lock()
	defer it.mu.Unlock()

	if !it.modified {
		if ((ipv6 && reflect.DeepEqual(table, it.v6Tables[id])) || (!ipv6 && reflect.DeepEqual(table, it.v4Tables[id]))) && !force {
			return
		}

		it.connections.init()
		it.startReaper(reaperDelay)
	}
	it.modified = true
	if ipv6 {
		it.v6Tables[id] = table
	} else {
		it.v4Tables[id] = table
	}
}

type chainVerdict int

const (
	chainAccept chainVerdict = iota

	chainDrop

	chainReturn
)

type checkTable struct {
	fn      checkTableFn
	tableID TableID
	table   Table
}

func (it *IPTables) shouldSkipOrPopulateTables(tables []checkTable, pkt *PacketBuffer) bool {
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
	default:
		return true
	}

	it.mu.RLock()
	defer it.mu.RUnlock()

	if !it.modified {
		return true
	}

	for i := range tables {
		table := &tables[i]
		table.table = it.getTableRLocked(table.tableID, pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber)
	}
	return false
}

func (it *IPTables) CheckPrerouting(pkt *PacketBuffer, addressEP AddressableEndpoint, inNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      check,
			tableID: RawID,
		},
		{
			fn:      check,
			tableID: MangleID,
		},
		{
			fn:      checkNAT,
			tableID: NATID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	pkt.tuple = it.connections.getConnAndUpdate(pkt, false)

	for _, table := range tables {
		if !table.fn(it, table.table, Prerouting, pkt, nil, addressEP, inNicName, "") {
			return false
		}
	}

	return true
}

func (it *IPTables) CheckInput(pkt *PacketBuffer, inNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      checkNAT,
			tableID: NATID,
		},
		{
			fn:      check,
			tableID: FilterID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	for _, table := range tables {
		if !table.fn(it, table.table, Input, pkt, nil, nil, inNicName, "") {
			return false
		}
	}

	if t := pkt.tuple; t != nil {
		pkt.tuple = nil
		return t.conn.finalize()
	}
	return true
}

func (it *IPTables) CheckForward(pkt *PacketBuffer, inNicName, outNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      check,
			tableID: FilterID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	for _, table := range tables {
		if !table.fn(it, table.table, Forward, pkt, nil, nil, inNicName, outNicName) {
			return false
		}
	}

	return true
}

func (it *IPTables) CheckOutput(pkt *PacketBuffer, r *Route, outNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      check,
			tableID: RawID,
		},
		{
			fn:      check,
			tableID: MangleID,
		},
		{
			fn:      checkNAT,
			tableID: NATID,
		},
		{
			fn:      check,
			tableID: FilterID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	pkt.tuple = it.connections.getConnAndUpdate(pkt, true)

	for _, table := range tables {
		if !table.fn(it, table.table, Output, pkt, r, nil, "", outNicName) {
			return false
		}
	}

	return true
}

func (it *IPTables) CheckPostrouting(pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, outNicName string) bool {
	tables := [...]checkTable{
		{
			fn:      check,
			tableID: MangleID,
		},
		{
			fn:      checkNAT,
			tableID: NATID,
		},
	}

	if it.shouldSkipOrPopulateTables(tables[:], pkt) {
		return true
	}

	for _, table := range tables {
		if !table.fn(it, table.table, Postrouting, pkt, r, addressEP, "", outNicName) {
			return false
		}
	}

	if t := pkt.tuple; t != nil {
		pkt.tuple = nil
		return t.conn.finalize()
	}
	return true
}

type checkTableFn func(it *IPTables, table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool

func checkNAT(it *IPTables, table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	return it.checkNAT(table, hook, pkt, r, addressEP, inNicName, outNicName)
}

func (it *IPTables) checkNAT(table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	t := pkt.tuple
	if t != nil && IPTHandlePacket(pkt, hook, r) {
		return true
	}

	if !it.check(table, hook, pkt, r, addressEP, inNicName, outNicName) {
		return false
	}

	if t == nil {
		return true
	}

	dnat, natDone := func() (bool, bool) {
		switch hook {
		case Prerouting, Output:
			return true, pkt.dnatDone
		case Input, Postrouting:
			return false, pkt.snatDone
		case Forward:
			panic("should not attempt NAT in forwarding")
		default:
			panic(fmt.Sprintf("unhandled hook = %d", hook))
		}
	}()

	if !natDone {
		IPTMaybePerformNoopNAT(pkt, hook, r, dnat)
	}

	return true
}

func check(it *IPTables, table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	return it.check(table, hook, pkt, r, addressEP, inNicName, outNicName)
}

func (it *IPTables) check(table Table, hook Hook, pkt *PacketBuffer, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) bool {
	ruleIdx := table.BuiltinChains[hook]
	switch verdict := it.checkChain(hook, pkt, table, ruleIdx, r, addressEP, inNicName, outNicName); verdict {
	case chainAccept:
		return true
	case chainDrop:
		return false
	case chainReturn:
		underflow := table.Rules[table.Underflows[hook]]
		switch v, _ := underflow.Target.Action(pkt, hook, r, addressEP); v {
		case RuleAccept:
			return true
		case RuleDrop:
			return false
		case RuleJump, RuleReturn:
			panic("Underflows should only return RuleAccept or RuleDrop.")
		default:
			panic(fmt.Sprintf("Unknown verdict: %d", v))
		}
	default:
		panic(fmt.Sprintf("Unknown verdict %v.", verdict))
	}
}

func (it *IPTables) beforeSave() {
	it.reaper.Stop()
	it.connections.mu.Lock()
}

func (it *IPTables) afterLoad(context.Context) {
	it.startReaper(reaperDelay)
}

func (it *IPTables) startReaper(interval time.Duration) {
	bucket := 0
	it.reaper = it.connections.clock.AfterFunc(interval, func() {
		bucket, interval = it.connections.reapUnused(bucket, interval)
		it.reaper.Reset(interval)
	})
}

func (it *IPTables) checkChain(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) chainVerdict {
	for ruleIdx < len(table.Rules) {
		switch verdict, jumpTo := it.checkRule(hook, pkt, table, ruleIdx, r, addressEP, inNicName, outNicName); verdict {
		case RuleAccept:
			return chainAccept

		case RuleDrop:
			return chainDrop

		case RuleReturn:
			return chainReturn

		case RuleJump:
			if jumpTo == ruleIdx+1 {
				ruleIdx++
				continue
			}
			switch verdict := it.checkChain(hook, pkt, table, jumpTo, r, addressEP, inNicName, outNicName); verdict {
			case chainAccept:
				return chainAccept
			case chainDrop:
				return chainDrop
			case chainReturn:
				ruleIdx++
				continue
			default:
				panic(fmt.Sprintf("Unknown verdict: %d", verdict))
			}

		default:
			panic(fmt.Sprintf("Unknown verdict: %d", verdict))
		}

	}

	return chainDrop
}

func (it *IPTables) checkRule(hook Hook, pkt *PacketBuffer, table Table, ruleIdx int, r *Route, addressEP AddressableEndpoint, inNicName, outNicName string) (RuleVerdict, int) {
	rule := table.Rules[ruleIdx]

	if !rule.Filter.match(pkt, hook, inNicName, outNicName) {
		return RuleJump, ruleIdx + 1
	}

	for _, matcher := range rule.Matchers {
		matches, hotdrop := matcher.Match(hook, pkt, inNicName, outNicName)
		if hotdrop {
			return RuleDrop, 0
		}
		if !matches {
			return RuleJump, ruleIdx + 1
		}
	}

	return rule.Target.Action(pkt, hook, r, addressEP)
}

func (it *IPTables) OriginalDst(epID TransportEndpointID, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber) (tcpip.Address, uint16, tcpip.Error) {
	it.mu.RLock()
	defer it.mu.RUnlock()
	if !it.modified {
		return tcpip.Address{}, 0, &tcpip.ErrNotConnected{}
	}
	return it.connections.originalDst(epID, netProto, transProto)
}
