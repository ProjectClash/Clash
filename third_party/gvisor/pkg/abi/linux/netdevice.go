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

	"github.com/metacubex/gvisor/pkg/common"
)

const (
	IFNAMSIZ = 16
)

type IFReq struct {
	_ structs.HostLayout
	IFName [IFNAMSIZ]byte

	Data [24]byte
}

func (ifr *IFReq) Name() string {
	for c := 0; c < len(ifr.IFName); c++ {
		if ifr.IFName[c] == 0 {
			return string(ifr.IFName[:c])
		}
	}
	return string(ifr.IFName[:])
}

func (ifr *IFReq) SetName(name string) {
	n := copy(ifr.IFName[:], []byte(name))
	common.ClearArray(ifr.IFName[n:])
}

var SizeOfIFReq = (*IFReq)(nil).SizeBytes()

type IFMap struct {
	_        structs.HostLayout
	MemStart uint64
	MemEnd   uint64
	BaseAddr int16
	IRQ      byte
	DMA      byte
	Port     byte
	_        [3]byte
}

type IFConf struct {
	_   structs.HostLayout
	Len int32
	_   [4]byte
	Ptr uint64
}

var SizeOfIFConf = (*IFConf)(nil).SizeBytes()

type EthtoolCmd uint32

const (
	ETHTOOL_GFEATURES EthtoolCmd = 0x3a
)

type EthtoolGFeatures struct {
	_    structs.HostLayout
	Cmd  uint32
	Size uint32
}

type EthtoolGetFeaturesBlock struct {
	_            structs.HostLayout
	Available    uint32
	Requested    uint32
	Active       uint32
	NeverChanged uint32
}

const (
	LOOPBACK_IFINDEX = 1
)
