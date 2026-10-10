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

package tcpip

import (
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
)

type SocketOptionsHandler interface {
	OnReuseAddressSet(v bool)

	OnReusePortSet(v bool)

	OnKeepAliveSet(v bool)

	OnDelayOptionSet(v bool)

	OnCorkOptionSet(v bool)

	LastError() Error

	UpdateLastError(err Error)

	HasNIC(v int32) bool

	OnSetSendBufferSize(v int64) (newSz int64)

	OnSetReceiveBufferSize(v, oldSz int64) (newSz int64, postSet func())

	WakeupWriters()

	GetAcceptConn() bool
}

type DefaultSocketOptionsHandler struct{}

var _ SocketOptionsHandler = (*DefaultSocketOptionsHandler)(nil)

func (*DefaultSocketOptionsHandler) OnReuseAddressSet(bool) {}

func (*DefaultSocketOptionsHandler) OnReusePortSet(bool) {}

func (*DefaultSocketOptionsHandler) OnKeepAliveSet(bool) {}

func (*DefaultSocketOptionsHandler) OnDelayOptionSet(bool) {}

func (*DefaultSocketOptionsHandler) OnCorkOptionSet(bool) {}

func (*DefaultSocketOptionsHandler) LastError() Error {
	return nil
}

func (*DefaultSocketOptionsHandler) UpdateLastError(Error) {}

func (*DefaultSocketOptionsHandler) HasNIC(int32) bool {
	return false
}

func (*DefaultSocketOptionsHandler) OnSetSendBufferSize(v int64) (newSz int64) {
	return v
}

func (*DefaultSocketOptionsHandler) WakeupWriters() {}

func (*DefaultSocketOptionsHandler) OnSetReceiveBufferSize(v, oldSz int64) (newSz int64, postSet func()) {
	return v, nil
}

func (*DefaultSocketOptionsHandler) GetAcceptConn() bool {
	return false
}

type StackHandler interface {
	Option(option any) Error

	TransportProtocolOption(proto TransportProtocolNumber, option GettableTransportProtocolOption) Error
}

type SocketOptions struct {
	handler SocketOptionsHandler

	stackHandler StackHandler `state:"manual"`


	broadcastEnabled atomicbitops.Uint32

	passCredEnabled atomicbitops.Uint32

	noChecksumEnabled atomicbitops.Uint32

	reuseAddressEnabled atomicbitops.Uint32

	reusePortEnabled atomicbitops.Uint32

	keepAliveEnabled atomicbitops.Uint32

	multicastLoopEnabled atomicbitops.Uint32

	receiveTOSEnabled atomicbitops.Uint32

	receiveTTLEnabled atomicbitops.Uint32

	receiveHopLimitEnabled atomicbitops.Uint32

	receiveTClassEnabled atomicbitops.Uint32

	receivePacketInfoEnabled atomicbitops.Uint32

	receiveIPv6PacketInfoEnabled atomicbitops.Uint32

	hdrIncludedEnabled atomicbitops.Uint32

	v6OnlyEnabled atomicbitops.Uint32

	quickAckEnabled atomicbitops.Uint32

	delayOptionEnabled atomicbitops.Uint32

	corkOptionEnabled atomicbitops.Uint32

	receiveOriginalDstAddress atomicbitops.Uint32

	ipv4RecvErrEnabled atomicbitops.Uint32

	ipv6RecvErrEnabled atomicbitops.Uint32

	errQueueMu sync.Mutex `state:"nosave"`
	errQueue   sockErrorList

	bindToDevice atomicbitops.Int32

	getSendBufferLimits GetSendBufferLimits `state:"manual"`

	sendBufferSize atomicbitops.Int64

	getReceiveBufferLimits GetReceiveBufferLimits `state:"manual"`

	receiveBufferSize atomicbitops.Int64

	rcvlowat atomicbitops.Int32

	experimentOptionValue atomicbitops.Uint32

	mark atomicbitops.Uint32

	mu sync.Mutex `state:"nosave"`

	linger LingerOption
}

func (so *SocketOptions) InitHandler(handler SocketOptionsHandler, stack StackHandler, getSendBufferLimits GetSendBufferLimits, getReceiveBufferLimits GetReceiveBufferLimits) {
	so.handler = handler
	so.stackHandler = stack
	so.getSendBufferLimits = getSendBufferLimits
	so.getReceiveBufferLimits = getReceiveBufferLimits
}

func storeAtomicBool(addr *atomicbitops.Uint32, v bool) {
	var val uint32
	if v {
		val = 1
	}
	addr.Store(val)
}

func (so *SocketOptions) SetLastError(err Error) {
	so.handler.UpdateLastError(err)
}

func (so *SocketOptions) GetBroadcast() bool {
	return so.broadcastEnabled.Load() != 0
}

func (so *SocketOptions) SetBroadcast(v bool) {
	storeAtomicBool(&so.broadcastEnabled, v)
}

func (so *SocketOptions) GetPassCred() bool {
	return so.passCredEnabled.Load() != 0
}

func (so *SocketOptions) SetPassCred(v bool) {
	storeAtomicBool(&so.passCredEnabled, v)
}

func (so *SocketOptions) GetNoChecksum() bool {
	return so.noChecksumEnabled.Load() != 0
}

func (so *SocketOptions) SetNoChecksum(v bool) {
	storeAtomicBool(&so.noChecksumEnabled, v)
}

func (so *SocketOptions) GetReuseAddress() bool {
	return so.reuseAddressEnabled.Load() != 0
}

func (so *SocketOptions) SetReuseAddress(v bool) {
	storeAtomicBool(&so.reuseAddressEnabled, v)
	so.handler.OnReuseAddressSet(v)
}

func (so *SocketOptions) GetReusePort() bool {
	return so.reusePortEnabled.Load() != 0
}

func (so *SocketOptions) SetReusePort(v bool) {
	storeAtomicBool(&so.reusePortEnabled, v)
	so.handler.OnReusePortSet(v)
}

func (so *SocketOptions) GetKeepAlive() bool {
	return so.keepAliveEnabled.Load() != 0
}

func (so *SocketOptions) SetKeepAlive(v bool) {
	storeAtomicBool(&so.keepAliveEnabled, v)
	so.handler.OnKeepAliveSet(v)
}

func (so *SocketOptions) GetMulticastLoop() bool {
	return so.multicastLoopEnabled.Load() != 0
}

func (so *SocketOptions) SetMulticastLoop(v bool) {
	storeAtomicBool(&so.multicastLoopEnabled, v)
}

func (so *SocketOptions) GetReceiveTOS() bool {
	return so.receiveTOSEnabled.Load() != 0
}

func (so *SocketOptions) SetReceiveTOS(v bool) {
	storeAtomicBool(&so.receiveTOSEnabled, v)
}

func (so *SocketOptions) GetReceiveTTL() bool {
	return so.receiveTTLEnabled.Load() != 0
}

func (so *SocketOptions) SetReceiveTTL(v bool) {
	storeAtomicBool(&so.receiveTTLEnabled, v)
}

func (so *SocketOptions) GetReceiveHopLimit() bool {
	return so.receiveHopLimitEnabled.Load() != 0
}

func (so *SocketOptions) SetReceiveHopLimit(v bool) {
	storeAtomicBool(&so.receiveHopLimitEnabled, v)
}

func (so *SocketOptions) GetReceiveTClass() bool {
	return so.receiveTClassEnabled.Load() != 0
}

func (so *SocketOptions) SetReceiveTClass(v bool) {
	storeAtomicBool(&so.receiveTClassEnabled, v)
}

func (so *SocketOptions) GetReceivePacketInfo() bool {
	return so.receivePacketInfoEnabled.Load() != 0
}

func (so *SocketOptions) SetReceivePacketInfo(v bool) {
	storeAtomicBool(&so.receivePacketInfoEnabled, v)
}

func (so *SocketOptions) GetIPv6ReceivePacketInfo() bool {
	return so.receiveIPv6PacketInfoEnabled.Load() != 0
}

func (so *SocketOptions) SetIPv6ReceivePacketInfo(v bool) {
	storeAtomicBool(&so.receiveIPv6PacketInfoEnabled, v)
}

func (so *SocketOptions) GetHeaderIncluded() bool {
	return so.hdrIncludedEnabled.Load() != 0
}

func (so *SocketOptions) SetHeaderIncluded(v bool) {
	storeAtomicBool(&so.hdrIncludedEnabled, v)
}

func (so *SocketOptions) GetV6Only() bool {
	return so.v6OnlyEnabled.Load() != 0
}

func (so *SocketOptions) SetV6Only(v bool) {
	storeAtomicBool(&so.v6OnlyEnabled, v)
}

func (so *SocketOptions) GetQuickAck() bool {
	return so.quickAckEnabled.Load() != 0
}

func (so *SocketOptions) SetQuickAck(v bool) {
	storeAtomicBool(&so.quickAckEnabled, v)
}

func (so *SocketOptions) GetDelayOption() bool {
	return so.delayOptionEnabled.Load() != 0
}

func (so *SocketOptions) SetDelayOption(v bool) {
	storeAtomicBool(&so.delayOptionEnabled, v)
	so.handler.OnDelayOptionSet(v)
}

func (so *SocketOptions) GetCorkOption() bool {
	return so.corkOptionEnabled.Load() != 0
}

func (so *SocketOptions) SetCorkOption(v bool) {
	storeAtomicBool(&so.corkOptionEnabled, v)
	so.handler.OnCorkOptionSet(v)
}

func (so *SocketOptions) GetReceiveOriginalDstAddress() bool {
	return so.receiveOriginalDstAddress.Load() != 0
}

func (so *SocketOptions) SetReceiveOriginalDstAddress(v bool) {
	storeAtomicBool(&so.receiveOriginalDstAddress, v)
}

func (so *SocketOptions) GetIPv4RecvError() bool {
	return so.ipv4RecvErrEnabled.Load() != 0
}

func (so *SocketOptions) SetIPv4RecvError(v bool) {
	storeAtomicBool(&so.ipv4RecvErrEnabled, v)
	if !v {
		so.pruneErrQueue()
	}
}

func (so *SocketOptions) GetIPv6RecvError() bool {
	return so.ipv6RecvErrEnabled.Load() != 0
}

func (so *SocketOptions) SetIPv6RecvError(v bool) {
	storeAtomicBool(&so.ipv6RecvErrEnabled, v)
	if !v {
		so.pruneErrQueue()
	}
}

func (so *SocketOptions) GetLastError() Error {
	return so.handler.LastError()
}

func (*SocketOptions) GetOutOfBandInline() bool {
	return true
}

func (*SocketOptions) SetOutOfBandInline(bool) {}

func (so *SocketOptions) GetLinger() LingerOption {
	so.mu.Lock()
	linger := so.linger
	so.mu.Unlock()
	return linger
}

func (so *SocketOptions) SetLinger(linger LingerOption) {
	so.mu.Lock()
	so.linger = linger
	so.mu.Unlock()
}

func (so *SocketOptions) GetExperimentOptionValue() uint16 {
	v := so.experimentOptionValue.Load()
	return uint16(v)
}

func (so *SocketOptions) SetExperimentOptionValue(v uint16) {
	so.experimentOptionValue.Store(uint32(v))
}

type SockErrOrigin uint8

const (
	SockExtErrorOriginNone SockErrOrigin = iota

	SockExtErrorOriginLocal

	SockExtErrorOriginICMP

	SockExtErrorOriginICMP6
)

func (origin SockErrOrigin) IsICMPErr() bool {
	return origin == SockExtErrorOriginICMP || origin == SockExtErrorOriginICMP6
}

type SockErrorCause interface {
	Origin() SockErrOrigin

	Type() uint8

	Code() uint8

	Info() uint32
}

type LocalSockError struct {
	info uint32
}

func (*LocalSockError) Origin() SockErrOrigin {
	return SockExtErrorOriginLocal
}

func (*LocalSockError) Type() uint8 {
	return 0
}

func (*LocalSockError) Code() uint8 {
	return 0
}

func (l *LocalSockError) Info() uint32 {
	return l.info
}

type SockError struct {
	sockErrorEntry

	Err Error
	Cause SockErrorCause

	Payload *buffer.View
	Dst FullAddress
	Offender FullAddress
	NetProto NetworkProtocolNumber
}

func (so *SocketOptions) pruneErrQueue() {
	so.errQueueMu.Lock()
	so.errQueue.Reset()
	so.errQueueMu.Unlock()
}

func (so *SocketOptions) DequeueErr() *SockError {
	so.errQueueMu.Lock()
	defer so.errQueueMu.Unlock()

	err := so.errQueue.Front()
	if err != nil {
		so.errQueue.Remove(err)
	}
	return err
}

func (so *SocketOptions) PeekErr() *SockError {
	so.errQueueMu.Lock()
	defer so.errQueueMu.Unlock()
	return so.errQueue.Front()
}

func (so *SocketOptions) QueueErr(err *SockError) {
	so.errQueueMu.Lock()
	defer so.errQueueMu.Unlock()
	so.errQueue.PushBack(err)
}

func (so *SocketOptions) QueueLocalErr(err Error, net NetworkProtocolNumber, info uint32, dst FullAddress, payload *buffer.View) {
	so.QueueErr(&SockError{
		Err:      err,
		Cause:    &LocalSockError{info: info},
		Payload:  payload,
		Dst:      dst,
		NetProto: net,
	})
}

func (so *SocketOptions) GetBindToDevice() int32 {
	return so.bindToDevice.Load()
}

func (so *SocketOptions) SetBindToDevice(bindToDevice int32) Error {
	if bindToDevice != 0 && !so.handler.HasNIC(bindToDevice) {
		return &ErrUnknownDevice{}
	}

	so.bindToDevice.Store(bindToDevice)
	return nil
}

func (so *SocketOptions) GetSendBufferSize() int64 {
	return so.sendBufferSize.Load()
}

func (so *SocketOptions) SendBufferLimits() (min, max int64) {
	limits := so.getSendBufferLimits(so.stackHandler)
	return int64(limits.Min), int64(limits.Max)
}

func (so *SocketOptions) SetSendBufferSize(sendBufferSize int64, notify bool) {
	if notify {
		sendBufferSize = so.handler.OnSetSendBufferSize(sendBufferSize)
	}
	so.sendBufferSize.Store(sendBufferSize)
	if notify {
		so.handler.WakeupWriters()
	}
}

func (so *SocketOptions) GetReceiveBufferSize() int64 {
	return so.receiveBufferSize.Load()
}

func (so *SocketOptions) ReceiveBufferLimits() (min, max int64) {
	limits := so.getReceiveBufferLimits(so.stackHandler)
	return int64(limits.Min), int64(limits.Max)
}

func (so *SocketOptions) SetReceiveBufferSize(receiveBufferSize int64, notify bool) {
	var postSet func()
	if notify {
		oldSz := so.receiveBufferSize.Load()
		receiveBufferSize, postSet = so.handler.OnSetReceiveBufferSize(receiveBufferSize, oldSz)
	}
	so.receiveBufferSize.Store(receiveBufferSize)
	if postSet != nil {
		postSet()
	}
}

func (so *SocketOptions) GetRcvlowat() int32 {
	defaultRcvlowat := int32(1)
	return defaultRcvlowat
}

func (so *SocketOptions) SetRcvlowat(rcvlowat int32) Error {
	so.rcvlowat.Store(rcvlowat)
	return nil
}

func (so *SocketOptions) GetAcceptConn() bool {
	return so.handler.GetAcceptConn()
}

func (so *SocketOptions) GetMark() uint32 {
	return so.mark.Load()
}

func (so *SocketOptions) SetMark(v uint32) {
	so.mark.Store(v)
}
