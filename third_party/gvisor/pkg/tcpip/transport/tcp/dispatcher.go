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

package tcp

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"golang.org/x/time/rate"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/sleep"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/hash/jenkins"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type epQueue struct {
	mu   epQueueMutex `state:"nosave"`
	list endpointList `state:"nosave"`
}

func (q *epQueue) enqueue(e *Endpoint) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e.pendingProcessingMu.Lock()
	defer e.pendingProcessingMu.Unlock()

	if e.pendingProcessing {
		return
	}
	q.list.PushBack(e)
	e.pendingProcessing = true
}

func (q *epQueue) dequeue() *Endpoint {
	q.mu.Lock()
	if e := q.list.Front(); e != nil {
		q.list.Remove(e)
		e.pendingProcessingMu.Lock()
		e.pendingProcessing = false
		e.pendingProcessingMu.Unlock()
		q.mu.Unlock()
		return e
	}
	q.mu.Unlock()
	return nil
}

func (q *epQueue) empty() bool {
	q.mu.Lock()
	v := q.list.Empty()
	q.mu.Unlock()
	return v
}

type processor struct {
	epQ              epQueue
	sleeper          sleep.Sleeper `state:"nosave"`
	newEndpointWaker sleep.Waker   `state:"nosave"`
	closeWaker       sleep.Waker   `state:"nosave"`
	pauseWaker       sleep.Waker   `state:"nosave"`
	pauseChan        chan struct{} `state:"nosave"`
	resumeChan       chan struct{} `state:"nosave"`
}

func (p *processor) close() {
	p.closeWaker.Assert()
}

func (p *processor) queueEndpoint(ep *Endpoint) {
	p.epQ.enqueue(ep)
	p.newEndpointWaker.Assert()
}

func deliverAccepted(ep *Endpoint) bool {
	lEP := ep.h.listenEP
	lEP.acceptMu.Lock()

	delete(lEP.acceptQueue.pendingEndpoints, ep)
	if lEP.acceptQueue.capacity == 0 {
		lEP.acceptMu.Unlock()
		return false
	}

	lEP.acceptQueue.endpoints.PushBack(ep)
	lEP.acceptMu.Unlock()
	ep.h.listenEP.waiterQueue.Notify(waiter.ReadableEvents)

	return true
}

func handleConnecting(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}
	cleanup := func() {
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
	if !ep.EndpointState().connecting() {
		ep.mu.Unlock()
		return
	}
	if err := ep.h.processSegments(); err != nil {
		if lEP := ep.h.listenEP; lEP != nil {
			lEP.acceptMu.Lock()
			delete(lEP.acceptQueue.pendingEndpoints, ep)
			lEP.acceptMu.Unlock()
		}
		ep.handshakeFailed(err)
		cleanup()
		return
	}

	if ep.EndpointState() == StateEstablished && ep.h.listenEP != nil {
		ep.isConnectNotified = true
		ep.stack.Stats().TCP.PassiveConnectionOpenings.Increment()
		if !deliverAccepted(ep) {
			ep.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			cleanup()
			return
		}
	}
	ep.mu.Unlock()
}

func handleConnected(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}

	if !ep.EndpointState().connected() {
		ep.mu.Unlock()
		return
	}

	switch err := ep.handleSegmentsLocked(); {
	case err != nil:
		ep.resetConnectionLocked(err)
		fallthrough
	case ep.EndpointState() == StateClose:
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	case ep.EndpointState() == StateTimeWait:
		startTimeWait(ep)
	}
	ep.mu.Unlock()
}

func startTimeWait(ep *Endpoint) {
	if ep.finWait2Timer != nil {
		ep.finWait2Timer.Stop()
	}
	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	timeWaitDuration := ep.getTimeWaitDuration()
	ep.timeWaitTimer = ep.stack.Clock().AfterFunc(timeWaitDuration, ep.timeWaitTimerExpired)
}

func handleTimeWait(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}

	if ep.EndpointState() != StateTimeWait {
		ep.mu.Unlock()
		return
	}

	extendTimeWait, reuseTW := ep.handleTimeWaitSegments()
	if reuseTW != nil {
		ep.transitionToStateCloseLocked()
		ep.mu.Unlock()
		ep.drainClosingSegmentQueue()
		ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		reuseTW()
		return
	}
	if extendTimeWait {
		ep.timeWaitTimer.Reset(ep.getTimeWaitDuration())
	}
	ep.mu.Unlock()
}

var warnRateLimiter = rate.NewLimiter(rate.Every(time.Second), 1)

func handleListen(ep *Endpoint) {
	if !ep.TryLock() {
		return
	}
	defer ep.mu.Unlock()

	if ep.EndpointState() != StateListen {
		return
	}

	for i := 0; i < maxSegmentsPerWake; i++ {
		s := ep.segmentQueue.dequeue()
		if s == nil {
			break
		}

		if err := ep.handleListenSegment(ep.listenCtx, s); err != nil {
			if warnRateLimiter.Allow() {
				log.Warningf("tcp.Endpoint.handleListenSegment() failed for packet [nic=%d, source=%s, dest=%s, protocol=%d]: %v", s.pkt.NICID, s.pkt.Network().SourceAddress(), s.pkt.Network().DestinationAddress(), s.pkt.NetworkProtocolNumber, err)
			}
		}
		s.DecRef()
	}
}

func (p *processor) start(wg *sync.WaitGroup) {
	defer wg.Done()
	defer p.sleeper.Done()

	for {
		switch w := p.sleeper.Fetch(true); {
		case w == &p.closeWaker:
			return
		case w == &p.pauseWaker:
			if !p.epQ.empty() {
				p.newEndpointWaker.Assert()
				p.pauseWaker.Assert()
				continue
			} else {
				p.pauseChan <- struct{}{}
				<-p.resumeChan
			}
		case w == &p.newEndpointWaker:
			for {
				ep := p.epQ.dequeue()
				if ep == nil {
					break
				}
				if ep.segmentQueue.empty() {
					continue
				}
				switch state := ep.EndpointState(); {
				case state.connecting():
					handleConnecting(ep)
				case state.connected() && state != StateTimeWait:
					handleConnected(ep)
				case state == StateTimeWait:
					handleTimeWait(ep)
				case state == StateListen:
					handleListen(ep)
				case state == StateError || state == StateClose:
					ep.mu.Lock()
					if st := ep.EndpointState(); st == StateError || st == StateClose {
						ep.drainClosingSegmentQueue()
					}
					ep.mu.Unlock()
				default:
					panic(fmt.Sprintf("unexpected tcp state in processor: %v", state))
				}
				if !ep.segmentQueue.empty() && !ep.isOwnedByUser() {
					p.epQ.enqueue(ep)
				}
			}
		}
	}
}

func (p *processor) pause() chan struct{} {
	p.pauseWaker.Assert()
	return p.pauseChan
}

func (p *processor) resume() {
	p.resumeChan <- struct{}{}
}

type dispatcher struct {
	processors []processor
	wg         sync.WaitGroup `state:"nosave"`
	hasher     jenkinsHasher
	mu         dispatcherMutex `state:"nosave"`
	paused bool
	closed bool
}

func (d *dispatcher) init(rng *rand.Rand, nProcessors int) {
	d.close()
	d.wait()

	d.mu.Lock()
	defer d.mu.Unlock()

	d.closed = false
	d.processors = make([]processor, nProcessors)
	d.hasher = jenkinsHasher{seed: rng.Uint32()}
	d.startLocked()
}

func (d *dispatcher) startLocked() {
	if d.closed {
		return
	}
	for i := range d.processors {
		p := &d.processors[i]
		p.sleeper.AddWaker(&p.newEndpointWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		p.sleeper.AddWaker(&p.pauseWaker)
		p.pauseChan = make(chan struct{})
		p.resumeChan = make(chan struct{})
		d.wg.Add(1)
		go p.start(&d.wg)
	}
}

func (d *dispatcher) start() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.startLocked()
}

func (d *dispatcher) close() {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	for i := range d.processors {
		d.processors[i].close()
	}
}

func (d *dispatcher) wait() {
	d.wg.Wait()
}

func (d *dispatcher) queuePacket(stackEP stack.TransportEndpoint, id stack.TransportEndpointID, clock tcpip.Clock, pkt *stack.PacketBuffer) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()

	if closed {
		return
	}

	ep := stackEP.(*Endpoint)

	s, err := newIncomingSegment(id, clock, pkt)
	if err != nil {
		ep.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		ep.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		return
	}
	defer s.DecRef()

	if !s.csumValid {
		ep.stack.Stats().TCP.ChecksumErrors.Increment()
		ep.stats.ReceiveErrors.ChecksumErrors.Increment()
		return
	}

	ep.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	ep.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		ep.stack.Stats().TCP.ResetsReceived.Increment()
	}

	if !ep.enqueueSegment(s) {
		return
	}

	if !ep.isOwnedByUser() {
		d.selectProcessor(id).queueEndpoint(ep)
	}
}

func (d *dispatcher) selectProcessor(id stack.TransportEndpointID) *processor {
	return &d.processors[d.hasher.hash(id)%uint32(len(d.processors))]
}

func (d *dispatcher) pause() {
	d.mu.Lock()
	d.paused = true
	d.mu.Unlock()
	for i := range d.processors {
		<-d.processors[i].pause()
	}
}

func (d *dispatcher) resume() {
	d.mu.Lock()

	if !d.paused {
		d.mu.Unlock()
		return
	}
	d.paused = false
	d.mu.Unlock()
	for i := range d.processors {
		d.processors[i].resume()
	}
}

type jenkinsHasher struct {
	seed uint32
}

func (j jenkinsHasher) hash(id stack.TransportEndpointID) uint32 {
	var payload [4]byte
	binary.LittleEndian.PutUint16(payload[0:], id.LocalPort)
	binary.LittleEndian.PutUint16(payload[2:], id.RemotePort)

	h := jenkins.Sum32(j.seed)
	h.Write(payload[:])
	h.Write(id.LocalAddress.AsSlice())
	h.Write(id.RemoteAddress.AsSlice())
	return h.Sum32()
}
