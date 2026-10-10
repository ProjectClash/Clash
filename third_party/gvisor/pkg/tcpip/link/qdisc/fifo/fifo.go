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

package fifo

import (
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/sleep"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/qdisc"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ stack.QueueingDiscipline = (*discipline)(nil)

const (
	BatchSize = 47

	qDiscClosed = 1
)

type discipline struct {
	wg          sync.WaitGroup `state:"nosave"`
	dispatchers []queueDispatcher

	closed atomicbitops.Int32
}

type queueDispatcher struct {
	lower stack.LinkWriter

	mu queueDispatcherMutex `state:"nosave"`
	queue qdisc.PacketBufferCircularList

	newPacketWaker sleep.Waker `state:"nosave"`
	closeWaker     sleep.Waker `state:"nosave"`
}

func New(lower stack.LinkWriter, n int, queueLen int) stack.QueueingDiscipline {
	d := &discipline{
		dispatchers: make([]queueDispatcher, n),
	}
	for i := range d.dispatchers {
		qd := &d.dispatchers[i]
		qd.lower = lower
		qd.queue.Init(queueLen)

		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			qd.dispatchLoop()
		}()
	}
	return d
}

func (qd *queueDispatcher) dispatchLoop() {
	s := sleep.Sleeper{}
	s.AddWaker(&qd.newPacketWaker)
	s.AddWaker(&qd.closeWaker)
	defer s.Done()

	var batch stack.PacketBufferList
	for {
		switch w := s.Fetch(true); w {
		case &qd.newPacketWaker:
		case &qd.closeWaker:
			qd.mu.Lock()
			for p := qd.queue.RemoveFront(); p != nil; p = qd.queue.RemoveFront() {
				p.DecRef()
			}
			qd.queue.DecRef()
			qd.mu.Unlock()
			return
		default:
			panic("unknown waker")
		}
		qd.mu.Lock()
		for pkt := qd.queue.RemoveFront(); pkt != nil; pkt = qd.queue.RemoveFront() {
			batch.PushBack(pkt)
			if batch.Len() < BatchSize && !qd.queue.IsEmpty() {
				continue
			}
			qd.mu.Unlock()
			_, _ = qd.lower.WritePackets(batch)
			batch.Reset()
			qd.mu.Lock()
		}
		qd.mu.Unlock()
	}
}

func (d *discipline) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	if d.closed.Load() == qDiscClosed {
		return &tcpip.ErrClosedForSend{}
	}
	qd := &d.dispatchers[int(pkt.Hash)%len(d.dispatchers)]
	qd.mu.Lock()
	if d.closed.Load() == qDiscClosed {
		qd.mu.Unlock()
		return &tcpip.ErrClosedForSend{}
	}
	haveSpace := qd.queue.HasSpace()
	if haveSpace {
		qd.queue.PushBack(pkt.IncRef())
	}
	qd.mu.Unlock()
	if !haveSpace {
		return &tcpip.ErrNoBufferSpace{}
	}
	qd.newPacketWaker.Assert()
	return nil
}

func (d *discipline) Close() {
	d.closed.Store(qDiscClosed)
	for i := range d.dispatchers {
		d.dispatchers[i].closeWaker.Assert()
	}
	d.wg.Wait()
}
