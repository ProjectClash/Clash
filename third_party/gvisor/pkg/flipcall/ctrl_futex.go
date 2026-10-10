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

//go:build !false
// +build !false

package flipcall

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/log"
)

type endpointControlImpl struct {
	state atomicbitops.Int32
}

const (
	epsBlocked = 1 << iota
	epsShutdown
)

func (ep *Endpoint) ctrlInit(opts ...EndpointOption) error {
	if len(opts) != 0 {
		return fmt.Errorf("unknown EndpointOption: %T", opts[0])
	}
	return nil
}

func (ep *Endpoint) ctrlConnect() error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	w := ep.NewWriter()
	if err := json.NewEncoder(w).Encode(struct{}{}); err != nil {
		return fmt.Errorf("error writing connection request: %v", err)
	}
	*ep.dataLen() = atomicbitops.FromUint32(w.Len())

	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	if err := ep.futexWakePeer(); err != nil {
		return err
	}
	if err := ep.futexWaitUntilActive(); err != nil {
		return err
	}

	var resp struct{}
	respLen := ep.dataLen().Load()
	if respLen > ep.dataCap {
		return fmt.Errorf("invalid connection response length %d (maximum %d)", respLen, ep.dataCap)
	}
	if err := json.NewDecoder(ep.NewReader(respLen)).Decode(&resp); err != nil {
		return fmt.Errorf("error reading connection response: %v", err)
	}

	return nil
}

func (ep *Endpoint) ctrlWaitFirst() error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	if err := ep.futexWaitUntilActive(); err != nil {
		return err
	}

	reqLen := ep.dataLen().Load()
	if reqLen > ep.dataCap {
		return fmt.Errorf("invalid connection request length %d (maximum %d)", reqLen, ep.dataCap)
	}
	var req struct{}
	if err := json.NewDecoder(ep.NewReader(reqLen)).Decode(&req); err != nil {
		return fmt.Errorf("error reading connection request: %v", err)
	}

	w := ep.NewWriter()
	if err := json.NewEncoder(w).Encode(struct{}{}); err != nil {
		return fmt.Errorf("error writing connection response: %v", err)
	}
	*ep.dataLen() = atomicbitops.FromUint32(w.Len())

	raceBecomeInactive()
	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	if err := ep.futexWakePeer(); err != nil {
		return err
	}

	return ep.futexWaitUntilActive()
}

func (ep *Endpoint) ctrlRoundTrip(mayRetainP bool) error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	if err := ep.futexWakePeer(); err != nil {
		return err
	}
	return ep.futexWaitUntilActive()
}

func (ep *Endpoint) ctrlWakeLast() error {
	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	return ep.futexWakePeer()
}

func (ep *Endpoint) enterFutexWait() error {
	switch eps := ep.ctrl.state.Add(epsBlocked); eps {
	case epsBlocked:
		return nil
	case epsBlocked | epsShutdown:
		ep.ctrl.state.Add(-epsBlocked)
		return ShutdownError{}
	default:
		panic(fmt.Sprintf("invalid flipcall.Endpoint.ctrl.state before flipcall.Endpoint.enterFutexWait(): %v", eps-epsBlocked))
	}
}

func (ep *Endpoint) exitFutexWait() {
	switch eps := ep.ctrl.state.Add(-epsBlocked); eps {
	case 0:
		return
	case epsShutdown:
		ep.shutdownConn()
	default:
		panic(fmt.Sprintf("invalid flipcall.Endpoint.ctrl.state after flipcall.Endpoint.exitFutexWait(): %v", eps+epsBlocked))
	}
}

func (ep *Endpoint) ctrlShutdown() {
	if ep.ctrl.state.Add(epsShutdown)&epsBlocked != 0 {
		for {
			if err := ep.futexWakeConnState(math.MaxInt32); err != nil {
				log.Warningf("failed to FUTEX_WAKE Endpoints: %v", err)
				break
			}
			yieldThread()
			if ep.ctrl.state.Load()&epsBlocked == 0 {
				break
			}
		}
	} else {
		ep.shutdownConn()
	}
}

func (ep *Endpoint) shutdownConn() {
	switch cs := ep.connState().Swap(csShutdown); cs {
	case ep.activeState:
		if err := ep.futexWakeConnState(1); err != nil {
			log.Warningf("failed to FUTEX_WAKE peer Endpoint for shutdown: %v", err)
		}
	case ep.inactiveState:
	case csShutdown:
	default:
		log.Warningf("unexpected connection state before Endpoint.shutdownConn(): %v", cs)
	}
}
