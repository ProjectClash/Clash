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

package syncevent

import (
	"github.com/metacubex/gvisor/pkg/sync"
)

type Broadcaster struct {

	mu sync.Mutex

	table []broadcasterSlot

	load int

	lastID SubscriptionID
}

type broadcasterSlot struct {
	receiver *Receiver
	filter   Set
	id       SubscriptionID
}

const (
	broadcasterMinNonZeroTableSize = 2

	broadcasterMaxLoadNum = 13
	broadcasterMaxLoadDen = 16
)

func (b *Broadcaster) SubscribeEvents(r *Receiver, filter Set) SubscriptionID {
	b.mu.Lock()

	b.lastID++
	id := b.lastID

	b.load++
	if (b.load * broadcasterMaxLoadDen) > (broadcasterMaxLoadNum * len(b.table)) {
		newlen := broadcasterMinNonZeroTableSize
		if len(b.table) != 0 {
			newlen = 2 * len(b.table)
		}
		if newlen <= cap(b.table) {
			newtable := b.table[:newlen]
			newmask := uint64(newlen - 1)
			for i := range b.table {
				if b.table[i].receiver != nil && uint64(b.table[i].id)&newmask != uint64(i) {
					entry := b.table[i]
					b.table[i] = broadcasterSlot{}
					broadcasterTableInsert(newtable, entry.id, entry.receiver, entry.filter)
				}
			}
			b.table = newtable
		} else {
			newtable := make([]broadcasterSlot, newlen)
			for i := range b.table {
				if b.table[i].receiver != nil {
					broadcasterTableInsert(newtable, b.table[i].id, b.table[i].receiver, b.table[i].filter)
				}
			}
			b.table = newtable
		}
	}

	broadcasterTableInsert(b.table, id, r, filter)
	b.mu.Unlock()
	return id
}

func broadcasterTableInsert(table []broadcasterSlot, id SubscriptionID, r *Receiver, filter Set) {
	entry := broadcasterSlot{
		receiver: r,
		filter:   filter,
		id:       id,
	}
	mask := uint64(len(table) - 1)
	i := uint64(id) & mask
	disp := uint64(0)
	for {
		if table[i].receiver == nil {
			table[i] = entry
			return
		}
		slotDisp := (i - uint64(table[i].id)) & mask
		if disp > slotDisp {
			table[i], entry = entry, table[i]
			disp = slotDisp
		}
		i = (i + 1) & mask
		disp++
	}
}

func (b *Broadcaster) UnsubscribeEvents(id SubscriptionID) {
	b.mu.Lock()

	mask := uint64(len(b.table) - 1)
	i := uint64(id) & mask
	for {
		if b.table[i].id == id {
			for {
				next := (i + 1) & mask
				if b.table[next].receiver == nil {
					break
				}
				if uint64(b.table[next].id)&mask == next {
					break
				}
				b.table[i] = b.table[next]
				i = next
			}
			b.table[i] = broadcasterSlot{}
			break
		}
		i = (i + 1) & mask
	}

	b.load--
	if len(b.table) > broadcasterMinNonZeroTableSize && (b.load*(4*broadcasterMaxLoadDen)) <= (broadcasterMaxLoadNum*len(b.table)) {
		newlen := len(b.table) / 2
		newtable := b.table[:newlen]
		for i := newlen; i < len(b.table); i++ {
			if b.table[i].receiver != nil {
				broadcasterTableInsert(newtable, b.table[i].id, b.table[i].receiver, b.table[i].filter)
				b.table[i] = broadcasterSlot{}
			}
		}
		b.table = newtable
	}

	b.mu.Unlock()
}

func (b *Broadcaster) Broadcast(events Set) {
	b.mu.Lock()
	for i := range b.table {
		if intersection := events & b.table[i].filter; intersection != 0 {
			b.table[i].receiver.Notify(intersection)
		}
	}
	b.mu.Unlock()
}

func (b *Broadcaster) FilteredEvents() Set {
	var es Set
	b.mu.Lock()
	for i := range b.table {
		es |= b.table[i].filter
	}
	b.mu.Unlock()
	return es
}
