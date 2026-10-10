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

package tcp

import (
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

type TSOffset struct {
	milliseconds uint32
}

func NewTSOffset(milliseconds uint32) TSOffset {
	return TSOffset{
		milliseconds: milliseconds,
	}
}

func (offset TSOffset) TSVal(now tcpip.MonotonicTime) uint32 {
	return uint32(now.Sub(tcpip.MonotonicTime{}).Milliseconds()) + offset.milliseconds
}

func (offset TSOffset) Elapsed(now tcpip.MonotonicTime, tsEcr uint32) time.Duration {
	return time.Duration(offset.TSVal(now)-tsEcr) * time.Millisecond
}
