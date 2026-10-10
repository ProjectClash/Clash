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

package ip

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

type ForwardingError interface {
	isForwardingError()
	fmt.Stringer
}

type ErrTTLExceeded struct{}

func (*ErrTTLExceeded) isForwardingError() {}

func (*ErrTTLExceeded) String() string { return "ttl exceeded" }

type ErrOutgoingDeviceNoBufferSpace struct{}

func (*ErrOutgoingDeviceNoBufferSpace) isForwardingError() {}

func (*ErrOutgoingDeviceNoBufferSpace) String() string { return "no device buffer space" }

type ErrParameterProblem struct{}

func (*ErrParameterProblem) isForwardingError() {}

func (*ErrParameterProblem) String() string { return "parameter problem" }

type ErrInitializingSourceAddress struct{}

func (*ErrInitializingSourceAddress) isForwardingError() {}

func (*ErrInitializingSourceAddress) String() string { return "initializing source address" }

type ErrLinkLocalSourceAddress struct{}

func (*ErrLinkLocalSourceAddress) isForwardingError() {}

func (*ErrLinkLocalSourceAddress) String() string { return "link local source address" }

type ErrLinkLocalDestinationAddress struct{}

func (*ErrLinkLocalDestinationAddress) isForwardingError() {}

func (*ErrLinkLocalDestinationAddress) String() string { return "link local destination address" }

type ErrHostUnreachable struct{}

func (*ErrHostUnreachable) isForwardingError() {}

func (*ErrHostUnreachable) String() string { return "no route to host" }

type ErrMessageTooLong struct{}

func (*ErrMessageTooLong) isForwardingError() {}

func (*ErrMessageTooLong) String() string { return "message too long" }

type ErrNoMulticastPendingQueueBufferSpace struct{}

func (*ErrNoMulticastPendingQueueBufferSpace) isForwardingError() {}

func (*ErrNoMulticastPendingQueueBufferSpace) String() string { return "no buffer space" }

type ErrUnexpectedMulticastInputInterface struct{}

func (*ErrUnexpectedMulticastInputInterface) isForwardingError() {}

func (*ErrUnexpectedMulticastInputInterface) String() string { return "unexpected input interface" }

type ErrUnknownOutputEndpoint struct{}

func (*ErrUnknownOutputEndpoint) isForwardingError() {}

func (*ErrUnknownOutputEndpoint) String() string { return "unknown endpoint" }

type ErrOther struct {
	Err tcpip.Error
}

func (*ErrOther) isForwardingError() {}

func (e *ErrOther) String() string { return fmt.Sprintf("other tcpip error: %s", e.Err) }
