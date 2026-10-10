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
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type Forwarder struct {
	stack *stack.Stack

	maxInFlight int
	handler     func(*ForwarderRequest)

	mu       forwarderMutex
	inFlight map[stack.TransportEndpointID]struct{}
	listen   *listenContext
}

func NewForwarder(s *stack.Stack, rcvWnd, maxInFlight int, handler func(*ForwarderRequest)) *Forwarder {
	if rcvWnd == 0 {
		rcvWnd = DefaultReceiveBufferSize
	}
	return &Forwarder{
		stack:       s,
		maxInFlight: maxInFlight,
		handler:     handler,
		inFlight:    make(map[stack.TransportEndpointID]struct{}),
		listen:      newListenContext(s, protocolFromStack(s), nil, seqnum.Size(rcvWnd), true, 0),
	}
}

func (f *Forwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	s, err := newIncomingSegment(id, f.stack.Clock(), pkt)
	if err != nil {
		return false
	}
	defer s.DecRef()

	if !s.csumValid || !s.flags.Contains(header.TCPFlagSyn) || s.flags.Contains(header.TCPFlagAck) {
		return false
	}

	opts := parseSynSegmentOptions(s)

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.inFlight[id]; ok {
		return true
	}

	if len(f.inFlight) >= f.maxInFlight {
		f.stack.Stats().TCP.ForwardMaxInFlightDrop.Increment()
		return true
	}

	f.inFlight[id] = struct{}{}
	s.IncRef()
	go f.handler(&ForwarderRequest{
		forwarder:  f,
		segment:    s,
		synOptions: opts,
	})

	return true
}

type ForwarderRequest struct {
	mu         forwarderRequestMutex
	forwarder  *Forwarder
	segment    *segment
	synOptions header.TCPSynOptions
}

func (r *ForwarderRequest) ID() stack.TransportEndpointID {
	return r.segment.id
}

func (r *ForwarderRequest) Complete(sendReset bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.segment == nil {
		panic("Completing already completed forwarder request")
	}

	r.forwarder.mu.Lock()
	delete(r.forwarder.inFlight, r.segment.id)
	r.forwarder.mu.Unlock()

	if sendReset {
		replyWithReset(r.forwarder.stack, r.segment, stack.DefaultTOS, tcpip.UseDefaultIPv4TTL, tcpip.UseDefaultIPv6HopLimit)
	}

	r.segment.DecRef()
	r.segment = nil
	r.forwarder = nil
}

func (r *ForwarderRequest) CreateEndpoint(queue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.segment == nil {
		return nil, &tcpip.ErrInvalidEndpointState{}
	}

	f := r.forwarder
	ep, err := f.listen.performHandshake(r.segment, header.TCPSynOptions{
		MSS:           r.synOptions.MSS,
		WS:            r.synOptions.WS,
		TS:            r.synOptions.TS,
		TSVal:         r.synOptions.TSVal,
		TSEcr:         r.synOptions.TSEcr,
		SACKPermitted: r.synOptions.SACKPermitted,
	}, queue, nil)
	if err != nil {
		return nil, err
	}

	return ep, nil
}

func (r *ForwarderRequest) ForwardedPacketExperimentOption() (uint16, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.segment.pkt.ExperimentOptionValue()
}
