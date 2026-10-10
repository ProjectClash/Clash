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

package stack

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	maxPendingResolutions          = 64
	maxPendingPacketsPerResolution = 256
)

type pendingPacket struct {
	routeInfo RouteInfo
	pkt       *PacketBuffer
}

type packetsPendingLinkResolutionMu struct {
	packetsPendingLinkResolutionMutex

	packets map[<-chan struct{}][]pendingPacket

	cancelChans []<-chan struct{}
}

type packetsPendingLinkResolution struct {
	nic *nic
	mu  packetsPendingLinkResolutionMu `state:"nosave"`
}

func (f *packetsPendingLinkResolution) incrementOutgoingPacketErrors(pkt *PacketBuffer) {
	f.nic.stack.stats.IP.OutgoingPacketErrors.Increment()

	if ipEndpointStats, ok := f.nic.getNetworkEndpoint(pkt.NetworkProtocolNumber).Stats().(IPNetworkEndpointStats); ok {
		ipEndpointStats.IPStats().OutgoingPacketErrors.Increment()
	}
}

func (f *packetsPendingLinkResolution) init(nic *nic) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nic = nic
	f.mu.packets = make(map[<-chan struct{}][]pendingPacket)
}

func (f *packetsPendingLinkResolution) cancel() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch, pendingPackets := range f.mu.packets {
		for _, p := range pendingPackets {
			p.pkt.DecRef()
		}
		delete(f.mu.packets, ch)
	}
	f.mu.cancelChans = nil
}

func (f *packetsPendingLinkResolution) dequeue(ch <-chan struct{}, linkAddr tcpip.LinkAddress, err tcpip.Error) {
	f.mu.Lock()
	packets, ok := f.mu.packets[ch]
	delete(f.mu.packets, ch)

	if ok {
		for i, cancelChan := range f.mu.cancelChans {
			if cancelChan == ch {
				f.mu.cancelChans = append(f.mu.cancelChans[:i], f.mu.cancelChans[i+1:]...)
				break
			}
		}
	}

	f.mu.Unlock()

	if ok {
		f.dequeuePackets(packets, linkAddr, err)
	}
}

func (f *packetsPendingLinkResolution) enqueue(r *Route, pkt *PacketBuffer) tcpip.Error {
	f.mu.Lock()
	routeInfo, ch, err := r.resolvedFields(nil)
	switch err.(type) {
	case nil:
		f.mu.Unlock()
		pkt.EgressRoute = routeInfo
		return f.nic.writePacket(pkt)
	case *tcpip.ErrWouldBlock:
	default:
		f.mu.Unlock()
		return err
	}

	defer f.mu.Unlock()

	packets, ok := f.mu.packets[ch]
	packets = append(packets, pendingPacket{
		routeInfo: routeInfo,
		pkt:       pkt.Clone(),
	})

	if len(packets) > maxPendingPacketsPerResolution {
		f.incrementOutgoingPacketErrors(packets[0].pkt)
		packets[0].pkt.DecRef()
		packets[0] = pendingPacket{}
		packets = packets[1:]

		if numPackets := len(packets); numPackets != maxPendingPacketsPerResolution {
			panic(fmt.Sprintf("holding more queued packets than expected; got = %d, want <= %d", numPackets, maxPendingPacketsPerResolution))
		}
	}

	f.mu.packets[ch] = packets

	if ok {
		return nil
	}

	cancelledPackets := f.newCancelChannelLocked(ch)

	if len(cancelledPackets) != 0 {
		go f.dequeuePackets(cancelledPackets, "", &tcpip.ErrAborted{})
	}

	return nil
}

func (f *packetsPendingLinkResolution) newCancelChannelLocked(newCH <-chan struct{}) []pendingPacket {
	f.mu.cancelChans = append(f.mu.cancelChans, newCH)
	if len(f.mu.cancelChans) <= maxPendingResolutions {
		return nil
	}

	ch := f.mu.cancelChans[0]
	f.mu.cancelChans[0] = nil
	f.mu.cancelChans = f.mu.cancelChans[1:]
	if l := len(f.mu.cancelChans); l > maxPendingResolutions {
		panic(fmt.Sprintf("max pending resolutions reached; got %d active resolutions, max = %d", l, maxPendingResolutions))
	}

	packets, ok := f.mu.packets[ch]
	if !ok {
		panic("must have a packet queue for an uncancelled channel")
	}
	delete(f.mu.packets, ch)

	return packets
}

func (f *packetsPendingLinkResolution) dequeuePackets(packets []pendingPacket, linkAddr tcpip.LinkAddress, err tcpip.Error) {
	for _, p := range packets {
		if err == nil {
			p.routeInfo.RemoteLinkAddress = linkAddr
			p.pkt.EgressRoute = p.routeInfo
			_ = f.nic.writePacket(p.pkt)
		} else {
			f.incrementOutgoingPacketErrors(p.pkt)

			if linkResolvableEP, ok := f.nic.getNetworkEndpoint(p.pkt.NetworkProtocolNumber).(LinkResolvableNetworkEndpoint); ok {
				linkResolvableEP.HandleLinkResolutionFailure(p.pkt)
			}
		}
		p.pkt.DecRef()
	}
}
