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

package flipcall

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/memutil"
)

type Endpoint struct {
	packet uintptr

	dataCap uint32

	activeState uint32

	inactiveState uint32

	shutdown atomicbitops.Uint32

	ctrl endpointControlImpl
}

type EndpointSide int

const (
	ClientSide EndpointSide = iota

	ServerSide
)

func (ep *Endpoint) Init(side EndpointSide, pwd PacketWindowDescriptor, opts ...EndpointOption) error {
	switch side {
	case ClientSide:
		ep.activeState = csClientActive
		ep.inactiveState = csServerActive
	case ServerSide:
		ep.activeState = csServerActive
		ep.inactiveState = csClientActive
	default:
		return fmt.Errorf("invalid EndpointSide: %v", side)
	}
	if pwd.Length < pageSize {
		return fmt.Errorf("packet window size (%d) less than minimum (%d)", pwd.Length, pageSize)
	}
	if pwd.Length > math.MaxUint32 {
		return fmt.Errorf("packet window size (%d) exceeds maximum (%d)", pwd.Length, math.MaxUint32)
	}
	m, err := memutil.MapFile(0, uintptr(pwd.Length), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, uintptr(pwd.FD), uintptr(pwd.Offset))
	if err != nil {
		return fmt.Errorf("failed to mmap packet window: %v", err)
	}
	ep.packet = m
	ep.dataCap = uint32(pwd.Length) - uint32(PacketHeaderBytes)
	if err := ep.ctrlInit(opts...); err != nil {
		ep.unmapPacket()
		return err
	}
	return nil
}

func NewEndpoint(side EndpointSide, pwd PacketWindowDescriptor, opts ...EndpointOption) (*Endpoint, error) {
	var ep Endpoint
	if err := ep.Init(side, pwd, opts...); err != nil {
		return nil, err
	}
	return &ep, nil
}

type EndpointOption interface {
	isEndpointOption()
}

func (ep *Endpoint) Destroy() {
	ep.unmapPacket()
}

func (ep *Endpoint) unmapPacket() {
	unix.RawSyscall(unix.SYS_MUNMAP, ep.packet, uintptr(ep.dataCap)+PacketHeaderBytes, 0)
	ep.packet = 0
}

func (ep *Endpoint) Shutdown() {
	if ep.shutdown.Swap(1) != 0 {
		return
	}
	ep.ctrlShutdown()
}

func (ep *Endpoint) isShutdownLocally() bool {
	return ep.shutdown.Load() != 0
}

type ShutdownError struct{}

func (ShutdownError) Error() string {
	return "flipcall connection shutdown"
}

func (ep *Endpoint) DataCap() uint32 {
	return ep.dataCap
}

func (ep *Endpoint) DataAddr() uintptr {
	return ep.packet + PacketHeaderBytes
}

func (ep *Endpoint) DataEndAddr() uintptr {
	return ep.packet + PacketHeaderBytes + uintptr(ep.dataCap)
}

const (
	csClientActive = 0
	csServerActive = 1
	csShutdown     = 2
)

func (ep *Endpoint) Connect() error {
	err := ep.ctrlConnect()
	if err == nil {
		raceBecomeActive()
	}
	return err
}

func (ep *Endpoint) RecvFirst() (uint32, error) {
	if err := ep.ctrlWaitFirst(); err != nil {
		return 0, err
	}
	raceBecomeActive()
	recvDataLen := ep.dataLen().Load()
	if recvDataLen > ep.dataCap {
		return 0, fmt.Errorf("received packet with invalid datagram length %d (maximum %d)", recvDataLen, ep.dataCap)
	}
	return recvDataLen, nil
}

func (ep *Endpoint) SendRecv(dataLen uint32) (uint32, error) {
	return ep.sendRecv(dataLen, false)
}

func (ep *Endpoint) SendRecvFast(dataLen uint32) (uint32, error) {
	return ep.sendRecv(dataLen, true)
}

func (ep *Endpoint) sendRecv(dataLen uint32, mayRetainP bool) (uint32, error) {
	if dataLen > ep.dataCap {
		panic(fmt.Sprintf("attempting to send packet with datagram length %d (maximum %d)", dataLen, ep.dataCap))
	}
	ep.dataLen().RacyStore(dataLen)
	raceBecomeInactive()
	if err := ep.ctrlRoundTrip(mayRetainP); err != nil {
		return 0, err
	}
	raceBecomeActive()
	recvDataLen := ep.dataLen().Load()
	if recvDataLen > ep.dataCap {
		return 0, fmt.Errorf("received packet with invalid datagram length %d (maximum %d)", recvDataLen, ep.dataCap)
	}
	return recvDataLen, nil
}

func (ep *Endpoint) SendLast(dataLen uint32) error {
	if dataLen > ep.dataCap {
		panic(fmt.Sprintf("attempting to send packet with datagram length %d (maximum %d)", dataLen, ep.dataCap))
	}
	ep.dataLen().RacyStore(dataLen)
	raceBecomeInactive()
	if err := ep.ctrlWakeLast(); err != nil {
		return err
	}
	return nil
}
