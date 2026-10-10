// Copyright 2026 The gVisor Authors.
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

package tbf

import (
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/common"
	"github.com/metacubex/gvisor/pkg/sleep"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/qdisc"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

const (
	BatchSize = 47

	qDiscClosed = 1
)

var _ stack.QueueingDiscipline = (*discipline)(nil)

type discipline struct {
	lower  stack.LinkWriter
	clock  tcpip.Clock `state:"nosave"`
	rate   uint64
	burst  uint32
	buffer int64

	wg     sync.WaitGroup `state:"nosave"`
	closed atomicbitops.Int32

	newPacketWaker sleep.Waker `state:"nosave"`
	tokenWaker     sleep.Waker `state:"nosave"`
	closeWaker     sleep.Waker `state:"nosave"`

	mu queueMutex `state:"nosave"`
	queue qdisc.PacketBufferCircularList

	tokens         int64
	timeCheckpoint tcpip.MonotonicTime
	watchdog       tcpip.Timer `state:"nosave"`
}

func len2TimeNS(rate uint64, len uint32) uint64 {
	const nsecPerSec = 1000000000
	return uint64(len) * nsecPerSec / rate
}

func (d *discipline) dispatchLoop() {
	s := sleep.Sleeper{}
	s.AddWaker(&d.newPacketWaker)
	s.AddWaker(&d.tokenWaker)
	s.AddWaker(&d.closeWaker)
	defer s.Done()

	var batch stack.PacketBufferList
	for {
		switch w := s.Fetch(true); w {
		case &d.newPacketWaker, &d.tokenWaker:
		case &d.closeWaker:
			if d.watchdog != nil {
				d.watchdog.Stop()
			}
			d.mu.Lock()
			for p := d.queue.RemoveFront(); p != nil; p = d.queue.RemoveFront() {
				p.DecRef()
			}
			d.queue.DecRef()
			d.mu.Unlock()
			return
		default:
			panic("unknown waker")
		}

		d.mu.Lock()
		for pkt := d.queue.PeekFront(); pkt != nil; pkt = d.queue.PeekFront() {
			pktLen := pkt.Size()
			now := d.clock.NowMonotonic()
			toks := common.Min(now.Sub(d.timeCheckpoint).Nanoseconds(), d.buffer)
			toks += d.tokens
			if toks > d.buffer {
				toks = d.buffer
			}
			toks -= int64(len2TimeNS(d.rate, uint32(pktLen)))
			sufficientTokens := toks >= 0
			if !sufficientTokens {
				if d.watchdog != nil {
					d.watchdog.Stop()
				}
				d.watchdog = d.clock.AfterFunc(time.Duration(-toks), d.tokenWaker.Assert)
				break
			}
			d.queue.RemoveFront()
			d.timeCheckpoint = now
			d.tokens = toks
			batch.PushBack(pkt)

			possiblyAnotherPacket := batch.Len() < BatchSize && !d.queue.IsEmpty()
			if possiblyAnotherPacket {
				continue
			}
			d.mu.Unlock()
			_, _ = d.lower.WritePackets(batch)
			batch.Reset()
			d.mu.Lock()
		}
		if batch.Len() > 0 {
			d.mu.Unlock()
			_, _ = d.lower.WritePackets(batch)
			batch.Reset()
			d.mu.Lock()
		}
		d.mu.Unlock()
	}
}

func New(lower stack.LinkEndpoint, clock tcpip.Clock, rate uint64, burst, queueLen uint32) (stack.QueueingDiscipline, error) {
	if rate == 0 {
		return nil, fmt.Errorf("qdisc=tbf requires setting qdisc-tbf-rate")
	}

	if burst == 0 {
		return nil, fmt.Errorf("qdisc=tbf requires setting qdisc-tbf-burst")
	}

	if gsoEP, ok := lower.(stack.GSOEndpoint); ok {
		maxGSOPktLen := gsoEP.GSOMaxSize() + uint32(lower.MaxHeaderLength())
		if gsoEP.SupportedGSO() == stack.HostGSOSupported && burst < uint32(maxGSOPktLen) {
			return nil, fmt.Errorf("burst (%d bytes) is smaller than link's max GSO packet size (%d bytes); either increase burst or disable host GSO via --gso=false", burst, maxGSOPktLen)
		}
	}

	maxPktLen := lower.MTU() + uint32(lower.MaxHeaderLength())
	if burst < maxPktLen {
		return nil, fmt.Errorf("burst (%d bytes) is smaller than max packet length (%d bytes)", burst, maxPktLen)
	}

	buffer := int64(len2TimeNS(rate, burst))
	if buffer == 0 {
		return nil, fmt.Errorf("rate (%d bytes/sec) is too high relative to burst (%d bytes); reduce qdisc-tbf-rate or increase qdisc-tbf-burst", rate, burst)
	}

	d := &discipline{
		lower:          lower,
		clock:          clock,
		rate:           rate,
		burst:          burst,
		buffer:         buffer,
		tokens:         buffer,
		timeCheckpoint: clock.NowMonotonic(),
	}
	d.queue.Init(int(queueLen))
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.dispatchLoop()
	}()
	return d, nil
}

func (d *discipline) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	if d.closed.Load() == qDiscClosed {
		return &tcpip.ErrClosedForSend{}
	}

	if uint32(pkt.Size()) > d.burst {
		return &tcpip.ErrMessageTooLong{}
	}

	d.mu.Lock()
	if d.closed.Load() == qDiscClosed {
		d.mu.Unlock()
		return &tcpip.ErrClosedForSend{}
	}
	haveSpace := d.queue.HasSpace()
	if haveSpace {
		d.queue.PushBack(pkt.IncRef())
	}
	d.mu.Unlock()
	if !haveSpace {
		return &tcpip.ErrNoBufferSpace{}
	}

	d.newPacketWaker.Assert()
	return nil
}

func (d *discipline) Close() {
	d.closed.Store(qDiscClosed)
	d.closeWaker.Assert()
	d.wg.Wait()
}
