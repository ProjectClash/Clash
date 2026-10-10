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
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

const (
	MinBufferSize = 4 << 10

	DefaultBufferSize = 212 << 10

	DefaultMaxBufferSize = 4 << 20

	defaultTCPInvalidRateLimit = 500 * time.Millisecond
)

type TCPInvalidRateLimitOption time.Duration

func (s *Stack) SetOption(option any) tcpip.Error {
	switch v := option.(type) {
	case tcpip.SendBufferSizeOption:
		if v.Min < MinBufferSize {
			return &tcpip.ErrInvalidOptionValue{}
		}

		if v.Default < v.Min || v.Default > v.Max {
			return &tcpip.ErrInvalidOptionValue{}
		}

		s.mu.Lock()
		s.sendBufferSize = v
		s.mu.Unlock()
		return nil

	case tcpip.ReceiveBufferSizeOption:
		if v.Min < MinBufferSize {
			return &tcpip.ErrInvalidOptionValue{}
		}

		if v.Default < v.Min || v.Default > v.Max {
			return &tcpip.ErrInvalidOptionValue{}
		}

		s.mu.Lock()
		s.receiveBufferSize = v
		s.mu.Unlock()
		return nil

	case TCPInvalidRateLimitOption:
		if v < 0 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		s.mu.Lock()
		s.tcpInvalidRateLimit = time.Duration(v)
		s.mu.Unlock()
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (s *Stack) Option(option any) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.SendBufferSizeOption:
		s.mu.RLock()
		*v = s.sendBufferSize
		s.mu.RUnlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		s.mu.RLock()
		*v = s.receiveBufferSize
		s.mu.RUnlock()
		return nil

	case *TCPInvalidRateLimitOption:
		s.mu.RLock()
		*v = TCPInvalidRateLimitOption(s.tcpInvalidRateLimit)
		s.mu.RUnlock()
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}
