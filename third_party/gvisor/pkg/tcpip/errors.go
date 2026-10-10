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

package tcpip

import (
	"fmt"
)

type Error interface {
	isError()

	IgnoreStats() bool

	fmt.Stringer
}

const maxErrno = 134


type ErrAborted struct{}

func (*ErrAborted) isError() {}

func (*ErrAborted) IgnoreStats() bool {
	return false
}
func (*ErrAborted) String() string {
	return "operation aborted"
}

type ErrAddressFamilyNotSupported struct{}

func (*ErrAddressFamilyNotSupported) isError() {}

func (*ErrAddressFamilyNotSupported) IgnoreStats() bool {
	return false
}
func (*ErrAddressFamilyNotSupported) String() string {
	return "address family not supported by protocol"
}

type ErrAlreadyBound struct{}

func (*ErrAlreadyBound) isError() {}

func (*ErrAlreadyBound) IgnoreStats() bool {
	return true
}
func (*ErrAlreadyBound) String() string { return "endpoint already bound" }

type ErrAlreadyConnected struct{}

func (*ErrAlreadyConnected) isError() {}

func (*ErrAlreadyConnected) IgnoreStats() bool {
	return true
}
func (*ErrAlreadyConnected) String() string { return "endpoint is already connected" }

type ErrAlreadyConnecting struct{}

func (*ErrAlreadyConnecting) isError() {}

func (*ErrAlreadyConnecting) IgnoreStats() bool {
	return true
}
func (*ErrAlreadyConnecting) String() string { return "endpoint is already connecting" }

type ErrBadAddress struct{}

func (*ErrBadAddress) isError() {}

func (*ErrBadAddress) IgnoreStats() bool {
	return false
}
func (*ErrBadAddress) String() string { return "bad address" }

type ErrBadBuffer struct{}

func (*ErrBadBuffer) isError() {}

func (*ErrBadBuffer) IgnoreStats() bool {
	return false
}
func (*ErrBadBuffer) String() string { return "bad buffer" }

type ErrBadLocalAddress struct{}

func (*ErrBadLocalAddress) isError() {}

func (*ErrBadLocalAddress) IgnoreStats() bool {
	return false
}
func (*ErrBadLocalAddress) String() string { return "bad local address" }

type ErrBroadcastDisabled struct{}

func (*ErrBroadcastDisabled) isError() {}

func (*ErrBroadcastDisabled) IgnoreStats() bool {
	return false
}
func (*ErrBroadcastDisabled) String() string { return "broadcast socket option disabled" }

type ErrClosedForReceive struct{}

func (*ErrClosedForReceive) isError() {}

func (*ErrClosedForReceive) IgnoreStats() bool {
	return false
}
func (*ErrClosedForReceive) String() string { return "endpoint is closed for receive" }

type ErrClosedForSend struct{}

func (*ErrClosedForSend) isError() {}

func (*ErrClosedForSend) IgnoreStats() bool {
	return false
}
func (*ErrClosedForSend) String() string { return "endpoint is closed for send" }

type ErrConnectStarted struct{}

func (*ErrConnectStarted) isError() {}

func (*ErrConnectStarted) IgnoreStats() bool {
	return true
}
func (*ErrConnectStarted) String() string { return "connection attempt started" }

type ErrConnectionAborted struct{}

func (*ErrConnectionAborted) isError() {}

func (*ErrConnectionAborted) IgnoreStats() bool {
	return false
}
func (*ErrConnectionAborted) String() string { return "connection aborted" }

type ErrConnectionRefused struct{}

func (*ErrConnectionRefused) isError() {}

func (*ErrConnectionRefused) IgnoreStats() bool {
	return false
}
func (*ErrConnectionRefused) String() string { return "connection was refused" }

type ErrConnectionReset struct{}

func (*ErrConnectionReset) isError() {}

func (*ErrConnectionReset) IgnoreStats() bool {
	return false
}
func (*ErrConnectionReset) String() string { return "connection reset by peer" }

type ErrDestinationRequired struct{}

func (*ErrDestinationRequired) isError() {}

func (*ErrDestinationRequired) IgnoreStats() bool {
	return false
}
func (*ErrDestinationRequired) String() string { return "destination address is required" }

type ErrDuplicateAddress struct{}

func (*ErrDuplicateAddress) isError() {}

func (*ErrDuplicateAddress) IgnoreStats() bool {
	return false
}
func (*ErrDuplicateAddress) String() string { return "duplicate address" }

type ErrDuplicateNICID struct{}

func (*ErrDuplicateNICID) isError() {}

func (*ErrDuplicateNICID) IgnoreStats() bool {
	return false
}
func (*ErrDuplicateNICID) String() string { return "duplicate nic id" }

type ErrInvalidNICID struct{}

func (*ErrInvalidNICID) isError() {}

func (*ErrInvalidNICID) IgnoreStats() bool {
	return false
}
func (*ErrInvalidNICID) String() string { return "invalid nic id" }

type ErrInvalidEndpointState struct{}

func (*ErrInvalidEndpointState) isError() {}

func (*ErrInvalidEndpointState) IgnoreStats() bool {
	return false
}
func (*ErrInvalidEndpointState) String() string { return "endpoint is in invalid state" }

type ErrInvalidOptionValue struct{}

func (*ErrInvalidOptionValue) isError() {}

func (*ErrInvalidOptionValue) IgnoreStats() bool {
	return false
}
func (*ErrInvalidOptionValue) String() string { return "invalid option value specified" }

type ErrInvalidPortRange struct{}

func (*ErrInvalidPortRange) isError() {}

func (*ErrInvalidPortRange) IgnoreStats() bool {
	return true
}
func (*ErrInvalidPortRange) String() string { return "invalid port range" }

type ErrMalformedHeader struct{}

func (*ErrMalformedHeader) isError() {}

func (*ErrMalformedHeader) IgnoreStats() bool {
	return false
}
func (*ErrMalformedHeader) String() string { return "header is malformed" }

type ErrMessageTooLong struct{}

func (*ErrMessageTooLong) isError() {}

func (*ErrMessageTooLong) IgnoreStats() bool {
	return false
}
func (*ErrMessageTooLong) String() string { return "message too long" }

type ErrNetworkUnreachable struct{}

func (*ErrNetworkUnreachable) isError() {}

func (*ErrNetworkUnreachable) IgnoreStats() bool {
	return false
}
func (*ErrNetworkUnreachable) String() string { return "network is unreachable" }

type ErrNoBufferSpace struct{}

func (*ErrNoBufferSpace) isError() {}

func (*ErrNoBufferSpace) IgnoreStats() bool {
	return false
}
func (*ErrNoBufferSpace) String() string { return "no buffer space available" }

type ErrNoPortAvailable struct{}

func (*ErrNoPortAvailable) isError() {}

func (*ErrNoPortAvailable) IgnoreStats() bool {
	return false
}
func (*ErrNoPortAvailable) String() string { return "no ports are available" }

type ErrHostUnreachable struct{}

func (*ErrHostUnreachable) isError() {}

func (*ErrHostUnreachable) IgnoreStats() bool {
	return false
}
func (*ErrHostUnreachable) String() string { return "no route to host" }

type ErrHostDown struct{}

func (*ErrHostDown) isError() {}

func (*ErrHostDown) IgnoreStats() bool {
	return false
}
func (*ErrHostDown) String() string { return "host is down" }

type ErrNoNet struct{}

func (*ErrNoNet) isError() {}

func (*ErrNoNet) IgnoreStats() bool {
	return false
}
func (*ErrNoNet) String() string { return "machine is not on the network" }

type ErrNoSuchFile struct{}

func (*ErrNoSuchFile) isError() {}

func (*ErrNoSuchFile) IgnoreStats() bool {
	return false
}
func (*ErrNoSuchFile) String() string { return "no such file" }

type ErrNotConnected struct{}

func (*ErrNotConnected) isError() {}

func (*ErrNotConnected) IgnoreStats() bool {
	return false
}
func (*ErrNotConnected) String() string { return "endpoint not connected" }

type ErrNotPermitted struct{}

func (*ErrNotPermitted) isError() {}

func (*ErrNotPermitted) IgnoreStats() bool {
	return false
}
func (*ErrNotPermitted) String() string { return "operation not permitted" }

type ErrNotSupported struct{}

func (*ErrNotSupported) isError() {}

func (*ErrNotSupported) IgnoreStats() bool {
	return false
}
func (*ErrNotSupported) String() string { return "operation not supported" }

type ErrPortInUse struct{}

func (*ErrPortInUse) isError() {}

func (*ErrPortInUse) IgnoreStats() bool {
	return false
}
func (*ErrPortInUse) String() string { return "port is in use" }

type ErrQueueSizeNotSupported struct{}

func (*ErrQueueSizeNotSupported) isError() {}

func (*ErrQueueSizeNotSupported) IgnoreStats() bool {
	return false
}
func (*ErrQueueSizeNotSupported) String() string { return "queue size querying not supported" }

type ErrTimeout struct{}

func (*ErrTimeout) isError() {}

func (*ErrTimeout) IgnoreStats() bool {
	return false
}
func (*ErrTimeout) String() string { return "operation timed out" }

type ErrUnknownDevice struct{}

func (*ErrUnknownDevice) isError() {}

func (*ErrUnknownDevice) IgnoreStats() bool {
	return false
}
func (*ErrUnknownDevice) String() string { return "unknown device" }

type ErrUnknownNICID struct{}

func (*ErrUnknownNICID) isError() {}

func (*ErrUnknownNICID) IgnoreStats() bool {
	return false
}
func (*ErrUnknownNICID) String() string { return "unknown nic id" }

type ErrUnknownProtocol struct{}

func (*ErrUnknownProtocol) isError() {}

func (*ErrUnknownProtocol) IgnoreStats() bool {
	return false
}
func (*ErrUnknownProtocol) String() string { return "unknown protocol" }

type ErrUnknownProtocolOption struct{}

func (*ErrUnknownProtocolOption) isError() {}

func (*ErrUnknownProtocolOption) IgnoreStats() bool {
	return false
}
func (*ErrUnknownProtocolOption) String() string { return "unknown option for protocol" }

type ErrWouldBlock struct{}

func (*ErrWouldBlock) isError() {}

func (*ErrWouldBlock) IgnoreStats() bool {
	return true
}
func (*ErrWouldBlock) String() string { return "operation would block" }

type ErrMissingRequiredFields struct{}

func (*ErrMissingRequiredFields) isError() {}

func (*ErrMissingRequiredFields) IgnoreStats() bool {
	return true
}
func (*ErrMissingRequiredFields) String() string { return "missing required fields" }

type ErrMulticastInputCannotBeOutput struct{}

func (*ErrMulticastInputCannotBeOutput) isError() {}

func (*ErrMulticastInputCannotBeOutput) IgnoreStats() bool {
	return true
}
func (*ErrMulticastInputCannotBeOutput) String() string { return "output cannot contain input" }

type ErrEndpointBusy struct{}

func (*ErrEndpointBusy) isError() {}

func (*ErrEndpointBusy) IgnoreStats() bool {
	return true
}

func (*ErrEndpointBusy) String() string {
	return "operation cannot be completed because the endpoint is busy"
}

