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

const NumSoftIRQ = 10

type Sysinfo struct {
	_         structs.HostLayout
	Uptime    int64
	Loads     [3]uint64
	TotalRAM  uint64
	FreeRAM   uint64
	SharedRAM uint64
	BufferRAM uint64
	TotalSwap uint64
	FreeSwap  uint64
	Procs     uint16
	_         [6]byte
	TotalHigh uint64
	FreeHigh  uint64
	Unit      uint32 `marshal:"unaligned"`
}
