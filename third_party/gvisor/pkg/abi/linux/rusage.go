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

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"
)

const (
	RUSAGE_BOTH = -0x2

	RUSAGE_CHILDREN = -0x1
	RUSAGE_SELF     = 0x0
	RUSAGE_THREAD   = 0x1
)

type Rusage struct {
	_        structs.HostLayout
	UTime    Timeval
	STime    Timeval
	MaxRSS   int64
	IXRSS    int64
	IDRSS    int64
	ISRSS    int64
	MinFlt   int64
	MajFlt   int64
	NSwap    int64
	InBlock  int64
	OuBlock  int64
	MsgSnd   int64
	MsgRcv   int64
	NSignals int64
	NVCSw    int64
	NIvCSw   int64
}
