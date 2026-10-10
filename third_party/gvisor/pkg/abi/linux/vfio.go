// Copyright 2024 The gVisor Authors.
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
	VFIO_TYPE = ';'
	VFIO_BASE = 100

	VFIO_TYPE1_IOMMU     = 1
	VFIO_SPAPR_TCE_IOMMU = 2
	VFIO_TYPE1v2_IOMMU   = 3
)

const (
	VFIO_DEVICE_FLAGS_RESET = 1 << iota
	VFIO_DEVICE_FLAGS_PCI
	VFIO_DEVICE_FLAGS_PLATFORM
	VFIO_DEVICE_FLAGS_AMBA
	VFIO_DEVICE_FLAGS_CCW
	VFIO_DEVICE_FLAGS_AP
	VFIO_DEVICE_FLAGS_FSL_MC
	VFIO_DEVICE_FLAGS_CAPS
	VFIO_DEVICE_FLAGS_CDX
)

const (
	VFIO_REGION_INFO_FLAG_READ = 1 << iota
	VFIO_REGION_INFO_FLAG_WRITE
	VFIO_REGION_INFO_FLAG_MMAP
	VFIO_REGION_INFO_FLAG_CAPS
)

const (
	VFIO_IRQ_INFO_EVENTFD = 1 << iota
	VFIO_IRQ_INFO_MASKABLE
	VFIO_IRQ_INFO_AUTOMASKED
	VFIO_IRQ_INFO_NORESIZE
)

const (
	VFIO_IRQ_SET_DATA_NONE = 1 << iota
	VFIO_IRQ_SET_DATA_BOOL
	VFIO_IRQ_SET_DATA_EVENTFD
	VFIO_IRQ_SET_ACTION_MASK
	VFIO_IRQ_SET_ACTION_UNMASK
	VFIO_IRQ_SET_ACTION_TRIGGER

	VFIO_IRQ_SET_DATA_TYPE_MASK = VFIO_IRQ_SET_DATA_NONE |
		VFIO_IRQ_SET_DATA_BOOL |
		VFIO_IRQ_SET_DATA_EVENTFD
	VFIO_IRQ_SET_ACTION_TYPE_MASK = VFIO_IRQ_SET_ACTION_MASK |
		VFIO_IRQ_SET_ACTION_UNMASK |
		VFIO_IRQ_SET_ACTION_TRIGGER
)

const (
	VFIO_PCI_INTX_IRQ_INDEX = iota
	VFIO_PCI_MSI_IRQ_INDEX
	VFIO_PCI_MSIX_IRQ_INDEX
	VFIO_PCI_ERR_IRQ_INDEX
	VFIO_PCI_REQ_IRQ_INDEX
	VFIO_PCI_NUM_IRQS
)

const (
	VFIO_DMA_MAP_FLAG_READ = 1 << iota
	VFIO_DMA_MAP_FLAG_WRITE
	VFIO_DMA_MAP_FLAG_VADDR
)

const (
	VFIO_DMA_UNMAP_FLAG_GET_DIRTY_BITMAP = 1
)

var (
	VFIO_CHECK_EXTENSION        = IO(VFIO_TYPE, VFIO_BASE+1)
	VFIO_SET_IOMMU              = IO(VFIO_TYPE, VFIO_BASE+2)
	VFIO_GROUP_SET_CONTAINER    = IO(VFIO_TYPE, VFIO_BASE+4)
	VFIO_GROUP_UNSET_CONTAINER  = IO(VFIO_TYPE, VFIO_BASE+5)
	VFIO_GROUP_GET_DEVICE_FD    = IO(VFIO_TYPE, VFIO_BASE+6)
	VFIO_DEVICE_GET_INFO        = IO(VFIO_TYPE, VFIO_BASE+7)
	VFIO_DEVICE_GET_REGION_INFO = IO(VFIO_TYPE, VFIO_BASE+8)
	VFIO_DEVICE_GET_IRQ_INFO    = IO(VFIO_TYPE, VFIO_BASE+9)
	VFIO_DEVICE_SET_IRQS        = IO(VFIO_TYPE, VFIO_BASE+10)
	VFIO_DEVICE_RESET           = IO(VFIO_TYPE, VFIO_BASE+11)
	VFIO_IOMMU_MAP_DMA          = IO(VFIO_TYPE, VFIO_BASE+13)
	VFIO_IOMMU_UNMAP_DMA        = IO(VFIO_TYPE, VFIO_BASE+14)
)

type VFIODeviceInfo struct {
	_ structs.HostLayout
	VFIODeviceInfoMin
	CapOffset uint32
	pad       uint32
}

type VFIODeviceInfoMin struct {
	_     structs.HostLayout
	Argsz uint32
	Flags uint32
	NumRegions uint32
	NumIrqs uint32
}

type VFIORegionInfo struct {
	_     structs.HostLayout
	Argsz uint32
	Flags uint32
	Index uint32
	CapOffset uint32
	Size uint64
	Offset uint64
}

type VFIOIrqInfo struct {
	_     structs.HostLayout
	Argsz uint32
	Flags uint32
	Index uint32
	Count uint32
}

type VFIOIrqSet struct {
	_     structs.HostLayout
	Argsz uint32
	Flags uint32
	Index uint32
	Start uint32
	Count uint32
}

type VFIOIommuType1DmaMap struct {
	_     structs.HostLayout
	Argsz uint32
	Flags uint32
	Vaddr uint64
	IOVa uint64
	Size uint64
}

type VFIOIommuType1DmaUnmap struct {
	_     structs.HostLayout
	Argsz uint32
	Flags uint32
	IOVa uint64
	Size uint64
}
