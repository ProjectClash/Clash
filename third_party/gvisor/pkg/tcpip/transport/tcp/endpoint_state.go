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
	"context"
	"fmt"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var logDisconnectOnce sync.Once

func logDisconnect() {
	logDisconnectOnce.Do(func() {
		log.Infof("One or more TCP connections terminated during save restore")
	})
}

func (e *Endpoint) beforeSave() {
	e.segmentQueue.freeze()

	e.mu.Lock()
	defer e.mu.Unlock()

	epState := e.EndpointState()
	switch {
	case epState == StateInitial || epState == StateBound:
	case epState.connected() || epState.handshake():
		if !e.stack.GetAllowConnectedOnSave() && !e.route.HasSaveRestoreCapability() {
			if e.stack.GetRemoveConf() {
				e.terminateAtRestore = false
				if !e.stack.AllowLiveTCPMigration() {
					logDisconnect()
					e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
					e.mu.Unlock()
					e.Close()
					e.mu.Lock()
				}
			} else {
				e.terminateAtRestore = true
			}
		}
		fallthrough
	case epState == StateListen:
	case epState.closed():
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.EndpointState()))
	}

	e.stack.RegisterResumableEndpoint(e)
}

func (a *acceptQueue) saveEndpoints() []*Endpoint {
	acceptedEndpoints := make([]*Endpoint, a.endpoints.Len())
	for i, e := 0, a.endpoints.Front(); e != nil; i, e = i+1, e.Next() {
		acceptedEndpoints[i] = e.Value.(*Endpoint)
	}
	return acceptedEndpoints
}

func (a *acceptQueue) loadEndpoints(_ context.Context, acceptedEndpoints []*Endpoint) {
	for _, ep := range acceptedEndpoints {
		a.endpoints.PushBack(ep)
	}
}

func (e *Endpoint) saveState() EndpointState {
	return e.EndpointState()
}

var connectedLoading sync.WaitGroup
var listenLoading sync.WaitGroup
var connectingLoading sync.WaitGroup


func (e *Endpoint) loadState(_ context.Context, epState EndpointState) {
	if epState.connected() {
		connectedLoading.Add(1)
	}
	switch {
	case epState == StateListen:
		listenLoading.Add(1)
	case epState.connecting():
		connectingLoading.Add(1)
	}
	e.state.Store(uint32(epState))
}

func (e *Endpoint) afterLoad(ctx context.Context) {
	e.origEndpointState = e.state.RacyLoad()
	e.state = atomicbitops.FromUint32(uint32(StateInitial))
	e.stack.RegisterRestoredEndpoint(e)
}

func (e *Endpoint) closeEndpointAtRestore() {
	e.mu.Lock()
	defer e.mu.Unlock()

	epState := EndpointState(e.origEndpointState)
	if !epState.connected() && !epState.handshake() {
		log.Debugf("endpoint was marked to terminate at restore in a wrong state, ID: %+v state: %v", e.ID, epState)
		return
	}

	if epState.handshake() {
		connectedLoading.Wait()
		listenLoading.Wait()
	}

	e.purgeReadQueue()
	if epState.connected() {
		e.purgeWriteQueue()
		e.purgePendingRcvQueue()
		e.cleanupLocked()
	}
	e.state.Store(uint32(StateError))
	e.closeNoShutdownLocked()
	tcpip.DeleteDanglingEndpoint(e)

	if epState.connected() {
		connectedLoading.Done()
	} else {
		connectingLoading.Done()
	}
}

func (e *Endpoint) Restore(s *stack.Stack) {
	if !e.EndpointState().closed() {
		e.keepalive.timer.init(s.Clock(), timerHandler(e, e.keepaliveTimerExpired))
	}
	if snd := e.snd; snd != nil {
		snd.resendTimer.init(s.Clock(), timerHandler(e, e.snd.retransmitTimerExpired))
		snd.reorderTimer.init(s.Clock(), timerHandler(e, e.snd.rc.reorderTimerExpired))
		snd.probeTimer.init(s.Clock(), timerHandler(e, e.snd.probeTimerExpired))
		snd.corkTimer.init(s.Clock(), timerHandler(e, e.snd.corkTimerExpired))
	}
	e.ops.InitHandler(e, e.stack, GetTCPSendBufferLimits, GetTCPReceiveBufferLimits)
	e.segmentQueue.thaw()

	e.mu.Lock()
	id := e.ID
	terminateAtRestore := e.terminateAtRestore
	e.mu.Unlock()

	bind := func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.isPortReserved = true

		e.setEndpointState(StateBound)
	}

	if terminateAtRestore && !e.stack.AllowLiveTCPMigration() {
		e.closeEndpointAtRestore()
		return
	}

	epState := EndpointState(e.origEndpointState)
	switch {
	case epState.connected():
		if e.stack.AllowLiveTCPMigration() {
			netProto := e.NetProto
			switch e.TransportEndpointInfo.ID.LocalAddress.BitLen() {
			case header.IPv4AddressSizeBits:
				netProto = header.IPv4ProtocolNumber
			case header.IPv6AddressSizeBits:
				netProto = header.IPv6ProtocolNumber
			}
			r, err := e.stack.FindRoute(0, e.TransportEndpointInfo.ID.LocalAddress, e.TransportEndpointInfo.ID.RemoteAddress, netProto, false)
			if err != nil {
				e.closeEndpointAtRestore()
				log.Infof("Cannot find the route %+v", e.TransportEndpointInfo.ID)
				return
			}
			e.boundNICID = r.NICID()
			r.Release()
		}
		bind()
		if e.connectingAddress.BitLen() == 0 {
			e.connectingAddress = e.TransportEndpointInfo.ID.RemoteAddress
			if e.NetProto == header.IPv6ProtocolNumber && e.TransportEndpointInfo.ID.RemoteAddress.BitLen() != header.IPv6AddressSizeBits {
				e.connectingAddress = tcpip.AddrFrom16Slice(append(
					[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff},
					e.TransportEndpointInfo.ID.RemoteAddress.AsSlice()...,
				))
			}
		}
		e.scoreboard.Reset()
		e.stack.UnregisterTransportEndpoint(e.effectiveNetProtos, header.TCPProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
		e.mu.Lock()
		err := e.connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.TransportEndpointInfo.ID.RemotePort}, false)
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			log.Warningf("TCP endpoint connect failed for connected endpoint with ID: %+v err: %v", id, err)
			e.mu.Unlock()
			e.Close()
			connectedLoading.Done()
			return
		}
		e.state.Store(e.origEndpointState)
		log.Infof("connect success: %+v", e.TransportEndpointInfo.ID)
		switch epState {
		case StateFinWait2:
			e.finWait2Timer = e.stack.Clock().AfterFunc(e.tcpLingerTimeout, e.finWait2TimerExpired)
		case StateTimeWait:
			e.timeWaitTimer = e.stack.Clock().AfterFunc(e.getTimeWaitDuration(), e.timeWaitTimerExpired)
		}

		if e.ops.GetCorkOption() {
			e.snd.corkTimer.enable(MinRTO)
		}
		e.mu.Unlock()
		e.requeueOnRestore()
		connectedLoading.Done()
	case epState == StateListen:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			e.LockUser()
			e.setEndpointState(StateListen)
			rcvWnd := seqnum.Size(e.receiveBufferAvailable())
			e.listenCtx = newListenContext(e.stack, e.protocol, e, rcvWnd, e.ops.GetV6Only(), e.NetProto)
			e.UnlockUser()
			e.requeueOnRestore()
			listenLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateConnecting:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			bind()
			err := e.Connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.TransportEndpointInfo.ID.RemotePort})
			if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
				log.Warningf("TCP endpoint connect failed for connecting endpoint with ID: %+v err: %v", id, err)
				e.Close()
			}
			connectingLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateSynSent || epState == StateSynRecv:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			bind()
			e.mu.Lock()
			e.setEndpointState(epState)
			r, err := e.stack.FindRoute(e.boundNICID, e.TransportEndpointInfo.ID.LocalAddress, e.TransportEndpointInfo.ID.RemoteAddress, e.effectiveNetProtos[0], false)
			if err != nil {
				e.mu.Unlock()
				log.Warningf("FindRoute failed when restoring endpoint w/ ID: %+v err: %v", id, err)
				e.Close()
				connectingLoading.Done()
				tcpip.AsyncLoading.Done()
				return
			}
			e.route = r
			timer, err := newBackoffTimer(e.stack.Clock(), InitialRTO, MaxRTO, timerHandler(e, e.h.retransmitHandlerLocked))
			if err != nil {
				panic(fmt.Sprintf("newBackOffTimer(_, %s, %s, _) failed: %s", InitialRTO, MaxRTO, err))
			}
			e.h.retransmitTimer = timer
			connectingLoading.Done()
			tcpip.AsyncLoading.Done()
			e.mu.Unlock()
			e.requeueOnRestore()
		}()
	case epState == StateBound:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			connectingLoading.Wait()
			bind()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateClose:
		e.isPortReserved = false
		e.state.Store(uint32(StateClose))
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	case epState == StateError:
		e.state.Store(uint32(StateError))
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	}
}

func (e *Endpoint) Resume() {
	e.segmentQueue.thaw()
}

func (e *Endpoint) requeueOnRestore() {
	if e.segmentQueue.empty() || e.isOwnedByUser() {
		return
	}
	e.protocol.dispatcher.selectProcessor(e.TransportEndpointInfo.ID).queueEndpoint(e)
}
