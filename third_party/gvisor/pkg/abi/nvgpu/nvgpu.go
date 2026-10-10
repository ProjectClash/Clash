// Copyright 2023 The gVisor Authors.
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

package nvgpu

import (
	"fmt"
	"github.com/metacubex/gvisor/pkg/common/structs"
)

const (
	NV_MAJOR_DEVICE_NUMBER                = 195
	NV_MINOR_DEVICE_NUMBER_REGULAR_MAX    = 247
	NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE = 255

	NVIDIA_UVM_PRIMARY_MINOR_NUMBER = 0

	NV_CAP_DRV_MINOR_COUNT = 8192
)

type Handle struct {
	_   structs.HostLayout
	Val uint32
}

func (h Handle) String() string {
	return fmt.Sprintf("%#x", h.Val)
}

type P64 uint64

const (
	NV_MAX_DEVICES    = 32
	NV_MAX_SUBDEVICES = 8
)

const (
	CC_CHAN_ALLOC_IV_SIZE_DWORD    = 3
	CC_CHAN_ALLOC_NONCE_SIZE_DWORD = 8
)

type RS_ACCESS_MASK struct {
	_     structs.HostLayout
	Limbs [SDK_RS_ACCESS_MAX_LIMBS]uint32
}

const SDK_RS_ACCESS_MAX_LIMBS = 1

type RS_SHARE_POLICY struct {
	_          structs.HostLayout
	Target     uint32
	AccessMask RS_ACCESS_MASK
	Type       uint16
	Action     uint8
	Pad        [1]byte
}

type NvUUID [16]uint8

type HasStatus interface {
	GetStatus() uint32
	SetStatus(status uint32)
}
