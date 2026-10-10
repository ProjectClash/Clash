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
	"github.com/metacubex/gvisor/pkg/atomicbitops"
)

type Receiver struct {
	pending atomicbitops.Uint64

	cb ReceiverCallback
}

type ReceiverCallback interface {
	NotifyPending()
}

func (r *Receiver) Init(cb ReceiverCallback) {
	r.cb = cb
}

func (r *Receiver) Pending() Set {
	return Set(r.pending.Load())
}

func (r *Receiver) Notify(es Set) {
	p := Set(r.pending.Load())
	if p&es == es {
		return
	}
	if !r.pending.CompareAndSwap(uint64(p), uint64(p|es)) {
		atomicbitops.OrUint64(&r.pending, uint64(es))
	}
	r.cb.NotifyPending()
}

func (r *Receiver) Ack(es Set) {
	p := Set(r.pending.Load())
	if p&es == 0 {
		return
	}
	if !r.pending.CompareAndSwap(uint64(p), uint64(p&^es)) {
		atomicbitops.AndUint64(&r.pending, ^uint64(es))
	}
}

func (r *Receiver) PendingAndAckAll() Set {
	return Set(r.pending.Swap(0))
}
