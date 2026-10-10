// Copyright 2021 The gVisor Authors.
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

package noop

import (
	"fmt"
	"io"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type endpoint struct {
	tcpip.DefaultSocketOptionsHandler
	ops tcpip.SocketOptions
}

func New(stk *stack.Stack) tcpip.Endpoint {
	var ep endpoint
	ep.ops.InitHandler(&ep, stk, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	return &ep
}

func (*endpoint) Abort() {
}

func (*endpoint) Close() {
}

func (*endpoint) ModerateRecvBuf(int) {
}

func (*endpoint) SetOwner(tcpip.PacketOwner) {
}

func (*endpoint) Read(io.Writer, tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	return tcpip.ReadResult{}, &tcpip.ErrNotPermitted{}
}

func (*endpoint) Write(tcpip.Payloader, tcpip.WriteOptions) (int64, tcpip.Error) {
	return 0, &tcpip.ErrNotPermitted{}
}

func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Connect(tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotPermitted{}
}

func (*endpoint) Shutdown(tcpip.ShutdownFlags) tcpip.Error {
	return &tcpip.ErrNotPermitted{}
}

func (*endpoint) Listen(int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

func (*endpoint) Bind(tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotPermitted{}
}

func (*endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, &tcpip.ErrNotSupported{}
}

func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
}

func (*endpoint) Readiness(waiter.EventMask) waiter.EventMask {
	return 0
}

func (*endpoint) SetSockOpt(tcpip.SettableSocketOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*endpoint) SetSockOptInt(tcpip.SockOptInt, int) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*endpoint) GetSockOpt(tcpip.GettableSocketOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

func (*endpoint) GetSockOptInt(tcpip.SockOptInt) (int, tcpip.Error) {
	return 0, &tcpip.ErrUnknownProtocolOption{}
}

func (*endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	panic(fmt.Sprintf("unreachable: noop.endpoint should never be registered, but got packet: %+v", pkt))
}

func (*endpoint) State() uint32 {
	return 0
}

func (*endpoint) Wait() {
}

func (*endpoint) Release() {
}

func (*endpoint) LastError() tcpip.Error {
	return nil
}

func (ep *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &ep.ops
}

func (*endpoint) Info() tcpip.EndpointInfo {
	return &stack.TransportEndpointInfo{}
}

func (*endpoint) Stats() tcpip.EndpointStats {
	return &tcpip.TransportEndpointStats{}
}
