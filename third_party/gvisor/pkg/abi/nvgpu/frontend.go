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
	"github.com/metacubex/gvisor/pkg/common/structs"

	"github.com/metacubex/gvisor/pkg/marshal"
)

const NV_IOCTL_MAGIC = uint32('F')

const (
	NV_IOCTL_BASE              = 200
	NV_ESC_CARD_INFO           = NV_IOCTL_BASE + 0
	NV_ESC_REGISTER_FD         = NV_IOCTL_BASE + 1
	NV_ESC_ALLOC_OS_EVENT      = NV_IOCTL_BASE + 6
	NV_ESC_FREE_OS_EVENT       = NV_IOCTL_BASE + 7
	NV_ESC_CHECK_VERSION_STR   = NV_IOCTL_BASE + 10
	NV_ESC_ATTACH_GPUS_TO_FD   = NV_IOCTL_BASE + 12
	NV_ESC_SYS_PARAMS          = NV_IOCTL_BASE + 14
	NV_ESC_EXPORT_TO_DMABUF_FD = NV_IOCTL_BASE + 17
	NV_ESC_WAIT_OPEN_COMPLETE  = NV_IOCTL_BASE + 18

	NV_ESC_NUMA_INFO = NV_IOCTL_BASE + 15

	NV_ESC_RM_ALLOC_MEMORY               = 0x27
	NV_ESC_RM_FREE                       = 0x29
	NV_ESC_RM_CONTROL                    = 0x2a
	NV_ESC_RM_ALLOC                      = 0x2b
	NV_ESC_RM_DUP_OBJECT                 = 0x34
	NV_ESC_RM_SHARE                      = 0x35
	NV_ESC_RM_IDLE_CHANNELS              = 0x41
	NV_ESC_RM_VID_HEAP_CONTROL           = 0x4a
	NV_ESC_RM_MAP_MEMORY                 = 0x4e
	NV_ESC_RM_UNMAP_MEMORY               = 0x4f
	NV_ESC_RM_ALLOC_CONTEXT_DMA2         = 0x54
	NV_ESC_RM_MAP_MEMORY_DMA             = 0x57
	NV_ESC_RM_UNMAP_MEMORY_DMA           = 0x58
	NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO = 0x5e
)


type IoctlCardInfo struct {
	_             structs.HostLayout
	Valid         uint8
	Pad0          [3]byte
	PCIInfo       PCIInfo
	GPUID         uint32
	InterruptLine uint16
	Pad1          [2]byte
	RegAddress    uint64
	RegSize       uint64
	FBAddress     uint64
	FBSize        uint64
	MinorNumber   uint32
	DevName       [10]byte
	Pad2          [2]byte
}

type PCIInfo struct {
	_        structs.HostLayout
	Domain   uint32
	Bus      uint8
	Slot     uint8
	Function uint8
	Pad0     uint8
	VendorID uint16
	DeviceID uint16
}

type IoctlRegisterFD struct {
	_     structs.HostLayout
	CtlFD int32
}

type IoctlAllocOSEvent struct {
	_       structs.HostLayout
	HClient Handle
	HDevice Handle
	FD      uint32
	Status  uint32
}

func (p *IoctlAllocOSEvent) GetFrontendFD() int32 {
	return int32(p.FD)
}

func (p *IoctlAllocOSEvent) SetFrontendFD(fd int32) {
	p.FD = uint32(fd)
}

func (p *IoctlAllocOSEvent) GetStatus() uint32 {
	return p.Status
}

func (p *IoctlAllocOSEvent) SetStatus(status uint32) {
	p.Status = status
}

type IoctlFreeOSEvent struct {
	_       structs.HostLayout
	HClient Handle
	HDevice Handle
	FD      uint32
	Status  uint32
}

func (p *IoctlFreeOSEvent) GetFrontendFD() int32 {
	return int32(p.FD)
}

func (p *IoctlFreeOSEvent) SetFrontendFD(fd int32) {
	p.FD = uint32(fd)
}

func (p *IoctlFreeOSEvent) GetStatus() uint32 {
	return p.Status
}

func (p *IoctlFreeOSEvent) SetStatus(status uint32) {
	p.Status = status
}

type RMAPIVersion struct {
	_             structs.HostLayout
	Cmd           uint32
	Reply         uint32
	VersionString [64]byte
}

type IoctlSysParams struct {
	_            structs.HostLayout
	MemblockSize uint64
}

type IoctlWaitOpenComplete struct {
	_             structs.HostLayout
	Rc            int32
	AdapterStatus uint32
}

func (p *IoctlWaitOpenComplete) GetStatus() uint32 {
	return p.AdapterStatus
}

func (p *IoctlWaitOpenComplete) SetStatus(status uint32) {
	p.AdapterStatus = status
}

const NV_DMABUF_EXPORT_MAX_HANDLES = 128

type IoctlExportToDMABufFD struct {
	_            structs.HostLayout
	FD           int32
	HClient      Handle
	TotalObjects uint32
	NumObjects   uint32
	Index        uint32
	Pad0         uint32
	TotalSize    uint64
	Handles      [NV_DMABUF_EXPORT_MAX_HANDLES]Handle
	Offsets      [NV_DMABUF_EXPORT_MAX_HANDLES]uint64
	Sizes        [NV_DMABUF_EXPORT_MAX_HANDLES]uint64
	Status       uint32
	Pad1         uint32
}

func (p *IoctlExportToDMABufFD) GetFrontendFD() int32 { return p.FD }

func (p *IoctlExportToDMABufFD) SetFrontendFD(fd int32) { p.FD = fd }

func (p *IoctlExportToDMABufFD) GetStatus() uint32 { return p.Status }

func (p *IoctlExportToDMABufFD) SetStatus(status uint32) { p.Status = status }

type IoctlExportToDMABufFD_V570 struct {
	_            structs.HostLayout
	FD           int32
	HClient      Handle
	TotalObjects uint32
	NumObjects   uint32
	Index        uint32
	Pad0         uint32
	TotalSize    uint64
	MappingType  uint8
	Pad1         [3]byte
	Handles      [NV_DMABUF_EXPORT_MAX_HANDLES]Handle
	Pad2         uint32
	Offsets      [NV_DMABUF_EXPORT_MAX_HANDLES]uint64
	Sizes        [NV_DMABUF_EXPORT_MAX_HANDLES]uint64
	Status       uint32
	Pad3         uint32
}

func (p *IoctlExportToDMABufFD_V570) GetFrontendFD() int32 { return p.FD }

func (p *IoctlExportToDMABufFD_V570) SetFrontendFD(fd int32) { p.FD = fd }

func (p *IoctlExportToDMABufFD_V570) GetStatus() uint32 { return p.Status }

func (p *IoctlExportToDMABufFD_V570) SetStatus(status uint32) { p.Status = status }

type IoctlExportToDMABufFD_V580 struct {
	_            structs.HostLayout
	FD           int32
	HClient      Handle
	TotalObjects uint32
	NumObjects   uint32
	Index        uint32
	Pad0         uint32
	TotalSize    uint64
	MappingType  uint8
	AllowMmap    uint8
	Pad1         [2]byte
	Handles      [NV_DMABUF_EXPORT_MAX_HANDLES]Handle
	Pad2         uint32
	Offsets      [NV_DMABUF_EXPORT_MAX_HANDLES]uint64
	Sizes        [NV_DMABUF_EXPORT_MAX_HANDLES]uint64
	Status       uint32
	Pad3         uint32
}

func (p *IoctlExportToDMABufFD_V580) GetFrontendFD() int32 { return p.FD }

func (p *IoctlExportToDMABufFD_V580) SetFrontendFD(fd int32) { p.FD = fd }

func (p *IoctlExportToDMABufFD_V580) GetStatus() uint32 { return p.Status }

func (p *IoctlExportToDMABufFD_V580) SetStatus(status uint32) { p.Status = status }

type IoctlNVOS02ParametersWithFD struct {
	_      structs.HostLayout
	Params NVOS02_PARAMETERS
	FD     int32
	Pad0   [4]byte
}

func (p *IoctlNVOS02ParametersWithFD) GetStatus() uint32 {
	return p.Params.Status
}

func (p *IoctlNVOS02ParametersWithFD) SetStatus(status uint32) {
	p.Params.Status = status
}

type NVOS02_PARAMETERS struct {
	_             structs.HostLayout
	HRoot         Handle
	HObjectParent Handle
	HObjectNew    Handle
	HClass        ClassID
	Flags         uint32
	Pad0          [4]byte
	PMemory       P64
	Limit         uint64
	Status        uint32
	Pad1          [4]byte
}

const (
	NVOS02_FLAGS_ALLOC_SHIFT = 16
	NVOS02_FLAGS_ALLOC_MASK  = 0x3
	NVOS02_FLAGS_ALLOC_NONE  = 0x00000001

	NVOS02_FLAGS_MAPPING_SHIFT  = 30
	NVOS02_FLAGS_MAPPING_MASK   = 0x3
	NVOS02_FLAGS_MAPPING_NO_MAP = 0x00000001
)

type NVOS00_PARAMETERS struct {
	_             structs.HostLayout
	HRoot         Handle
	HObjectParent Handle
	HObjectOld    Handle
	Status        uint32
}

func (p *NVOS00_PARAMETERS) GetStatus() uint32 {
	return p.Status
}

func (p *NVOS00_PARAMETERS) SetStatus(status uint32) {
	p.Status = status
}

type RmAllocParamType interface {
	GetHClass() ClassID
	GetPAllocParms() P64
	GetPRightsRequested() P64
	SetPAllocParms(p P64)
	SetPRightsRequested(p P64)
	FromOS64(other NVOS64_PARAMETERS)
	ToOS64() NVOS64_PARAMETERS
	GetPointer() uintptr
	HasStatus
	marshal.Marshallable
}

func GetRmAllocParamObj(isNVOS64 bool) RmAllocParamType {
	if isNVOS64 {
		return &NVOS64_PARAMETERS{}
	}
	return &NVOS21_PARAMETERS{}
}

type NVOS21_PARAMETERS struct {
	_             structs.HostLayout
	HRoot         Handle
	HObjectParent Handle
	HObjectNew    Handle
	HClass        ClassID
	PAllocParms   P64
	ParamsSize    uint32
	Status        uint32
}

func (n *NVOS21_PARAMETERS) GetHClass() ClassID {
	return n.HClass
}

func (n *NVOS21_PARAMETERS) GetPAllocParms() P64 {
	return n.PAllocParms
}

func (n *NVOS21_PARAMETERS) GetPRightsRequested() P64 {
	return 0
}

func (n *NVOS21_PARAMETERS) SetPAllocParms(p P64) { n.PAllocParms = p }

func (n *NVOS21_PARAMETERS) SetPRightsRequested(p P64) {
	panic("impossible")
}

func (n *NVOS21_PARAMETERS) FromOS64(other NVOS64_PARAMETERS) {
	n.HRoot = other.HRoot
	n.HObjectParent = other.HObjectParent
	n.HObjectNew = other.HObjectNew
	n.HClass = other.HClass
	n.PAllocParms = other.PAllocParms
	n.ParamsSize = other.ParamsSize
	n.Status = other.Status
}

func (n *NVOS21_PARAMETERS) ToOS64() NVOS64_PARAMETERS {
	return NVOS64_PARAMETERS{
		HRoot:         n.HRoot,
		HObjectParent: n.HObjectParent,
		HObjectNew:    n.HObjectNew,
		HClass:        n.HClass,
		PAllocParms:   n.PAllocParms,
		ParamsSize:    n.ParamsSize,
		Status:        n.Status,
	}
}

func (n *NVOS21_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS21_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS55_PARAMETERS struct {
	_          structs.HostLayout
	HClient    Handle
	HParent    Handle
	HObject    Handle
	HClientSrc Handle
	HObjectSrc Handle
	Flags      uint32
	Status     uint32
}

func (n *NVOS55_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS55_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS57_PARAMETERS struct {
	_           structs.HostLayout
	HClient     Handle
	HObject     Handle
	SharePolicy RS_SHARE_POLICY
	Status      uint32
}

func (n *NVOS57_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS57_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS30_PARAMETERS struct {
	_           structs.HostLayout
	Client      Handle
	Device      Handle
	Channel     Handle
	NumChannels uint32

	Clients  P64
	Devices  P64
	Channels P64

	Flags   uint32
	Timeout uint32
	Status  uint32
	Pad0    [4]byte
}

func (n *NVOS30_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS30_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS32_PARAMETERS struct {
	_             structs.HostLayout
	HRoot         Handle
	HObjectParent Handle
	Function      uint32
	HVASpace      Handle
	IVCHeapNumber int16
	Pad           [2]byte
	Status        uint32
	Total         uint64
	Free          uint64
	Data          [144]byte
}

func (n *NVOS32_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS32_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

const (
	NVOS32_FUNCTION_ALLOC_SIZE = 2
)

type NVOS32AllocSize struct {
	_               structs.HostLayout
	Owner           uint32
	HMemory         Handle
	Type            uint32
	Flags           uint32
	Attr            uint32
	Format          uint32
	ComprCovg       uint32
	ZcullCovg       uint32
	PartitionStride uint32
	Width           uint32
	Height          uint32
	Pad0            [4]byte
	Size            uint64
	Alignment       uint64
	Offset          uint64
	Limit           uint64
	Address         P64
	RangeBegin      uint64
	RangeEnd        uint64
	Attr2           uint32
	CtagOffset      uint32
}

const (
	NVOS32_ALLOC_FLAGS_VIRTUAL = 0x00080000
)

const (
	NVOS32_ATTR_LOCATION_SHIFT  = 25
	NVOS32_ATTR_LOCATION_MASK   = 0x3
	NVOS32_ATTR_LOCATION_VIDMEM = 0
)

const (
	NVOS32_ATTR2_USE_EGM_SHIFT = 24
	NVOS32_ATTR2_USE_EGM_MASK  = 0x1
	NVOS32_ATTR2_USE_EGM_FALSE = 0
	NVOS32_ATTR2_USE_EGM_TRUE  = 1
)

type IoctlNVOS33ParametersWithFD struct {
	_      structs.HostLayout
	Params NVOS33_PARAMETERS
	FD     int32
	Pad0   [4]byte
}

func (p *IoctlNVOS33ParametersWithFD) GetStatus() uint32 {
	return p.Params.Status
}

func (p *IoctlNVOS33ParametersWithFD) SetStatus(status uint32) {
	p.Params.Status = status
}

type NVOS33_PARAMETERS struct {
	_              structs.HostLayout
	HClient        Handle
	HDevice        Handle
	HMemory        Handle
	Pad0           [4]byte
	Offset         uint64
	Length         uint64
	PLinearAddress P64
	Status         uint32
	Flags          uint32
}

const (
	NVOS33_FLAGS_CACHING_TYPE_SHIFT         = 23
	NVOS33_FLAGS_CACHING_TYPE_MASK          = 0x7
	NVOS33_FLAGS_CACHING_TYPE_CACHED        = 0
	NVOS33_FLAGS_CACHING_TYPE_UNCACHED      = 1
	NVOS33_FLAGS_CACHING_TYPE_WRITECOMBINED = 2
	NVOS33_FLAGS_CACHING_TYPE_WRITEBACK     = 5
	NVOS33_FLAGS_CACHING_TYPE_DEFAULT       = 6
	NVOS33_FLAGS_CACHING_TYPE_UNCACHED_WEAK = 7
)

type NVOS34_PARAMETERS struct {
	_              structs.HostLayout
	HClient        Handle
	HDevice        Handle
	HMemory        Handle
	Pad0           [4]byte
	PLinearAddress P64
	Status         uint32
	Flags          uint32
}

func (n *NVOS34_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS34_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS39_PARAMETERS struct {
	_             structs.HostLayout
	HObjectParent Handle
	HSubDevice    Handle
	HObjectNew    Handle
	HClass        ClassID
	Flags         uint32
	Selector      uint32
	HMemory       Handle
	Pad0          [4]byte
	Offset        uint64
	Limit         uint64
	Status        uint32
	Pad1          [4]byte
}

func (n *NVOS39_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS39_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS46_PARAMETERS struct {
	_         structs.HostLayout
	Client    Handle
	Device    Handle
	Dma       Handle
	Memory    Handle
	Offset    uint64
	Length    uint64
	Flags     uint32
	Pad0      [4]byte
	DmaOffset uint64
	Status    uint32
	Pad1      [4]byte
}

func (n *NVOS46_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS46_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS46_PARAMETERS_V580 struct {
	_            structs.HostLayout
	Client       Handle
	Device       Handle
	Dma          Handle
	Memory       Handle
	Offset       uint64
	Length       uint64
	Flags        uint32
	Flags2       uint32
	KindOverride uint32
	Pad0         [4]byte
	DmaOffset    uint64
	Status       uint32
	Pad1         [4]byte
}

func (n *NVOS46_PARAMETERS_V580) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS46_PARAMETERS_V580) SetStatus(status uint32) {
	n.Status = status
}

type NVOS47_PARAMETERS struct {
	_         structs.HostLayout
	Client    Handle
	Device    Handle
	Dma       Handle
	Memory    Handle
	Flags     uint32
	Pad0      [4]byte
	DmaOffset uint64
	Status    uint32
	Pad1      [4]byte
}

func (n *NVOS47_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS47_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS47_PARAMETERS_V550 struct {
	_         structs.HostLayout
	Client    Handle
	Device    Handle
	Dma       Handle
	Memory    Handle
	Flags     uint32
	Pad0      [4]byte
	DmaOffset uint64
	Size      uint64
	Status    uint32
	Pad1      [4]byte
}

func (n *NVOS47_PARAMETERS_V550) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS47_PARAMETERS_V550) SetStatus(status uint32) {
	n.Status = status
}

type NVOS54_PARAMETERS struct {
	_          structs.HostLayout
	HClient    Handle
	HObject    Handle
	Cmd        uint32
	Flags      uint32
	Params     P64
	ParamsSize uint32
	Status     uint32
}

func (n *NVOS54_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS54_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS56_PARAMETERS struct {
	_              structs.HostLayout
	HClient        Handle
	HDevice        Handle
	HMemory        Handle
	Pad0           [4]byte
	POldCPUAddress P64
	PNewCPUAddress P64
	Status         uint32
	Pad1           [4]byte
}

func (n *NVOS56_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS56_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type NVOS64_PARAMETERS struct {
	_                structs.HostLayout
	HRoot            Handle
	HObjectParent    Handle
	HObjectNew       Handle
	HClass           ClassID
	PAllocParms      P64
	PRightsRequested P64
	ParamsSize       uint32
	Flags            uint32
	Status           uint32
	_                uint32
}

func (n *NVOS64_PARAMETERS) GetHClass() ClassID {
	return n.HClass
}

func (n *NVOS64_PARAMETERS) GetPAllocParms() P64 {
	return n.PAllocParms
}

func (n *NVOS64_PARAMETERS) GetPRightsRequested() P64 {
	return n.PRightsRequested
}

func (n *NVOS64_PARAMETERS) SetPAllocParms(p P64) { n.PAllocParms = p }

func (n *NVOS64_PARAMETERS) SetPRightsRequested(p P64) { n.PRightsRequested = p }

func (n *NVOS64_PARAMETERS) FromOS64(other NVOS64_PARAMETERS) { *n = other }

func (n *NVOS64_PARAMETERS) ToOS64() NVOS64_PARAMETERS { return *n }

func (n *NVOS64_PARAMETERS) GetStatus() uint32 {
	return n.Status
}

func (n *NVOS64_PARAMETERS) SetStatus(status uint32) {
	n.Status = status
}

type HasFrontendFD interface {
	GetFrontendFD() int32
	SetFrontendFD(int32)
}

var (
	SizeofIoctlRegisterFD             = uint32((*IoctlRegisterFD)(nil).SizeBytes())
	SizeofIoctlAllocOSEvent           = uint32((*IoctlAllocOSEvent)(nil).SizeBytes())
	SizeofIoctlFreeOSEvent            = uint32((*IoctlFreeOSEvent)(nil).SizeBytes())
	SizeofRMAPIVersion                = uint32((*RMAPIVersion)(nil).SizeBytes())
	SizeofIoctlSysParams              = uint32((*IoctlSysParams)(nil).SizeBytes())
	SizeofIoctlWaitOpenComplete       = uint32((*IoctlWaitOpenComplete)(nil).SizeBytes())
	SizeofIoctlNVOS02ParametersWithFD = uint32((*IoctlNVOS02ParametersWithFD)(nil).SizeBytes())
	SizeofNVOS00Parameters            = uint32((*NVOS00_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS21Parameters            = uint32((*NVOS21_PARAMETERS)(nil).SizeBytes())
	SizeofIoctlNVOS33ParametersWithFD = uint32((*IoctlNVOS33ParametersWithFD)(nil).SizeBytes())
	SizeofNVOS30Parameters            = uint32((*NVOS30_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS32Parameters            = uint32((*NVOS32_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS34Parameters            = uint32((*NVOS34_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS39Parameters            = uint32((*NVOS39_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS54Parameters            = uint32((*NVOS54_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS55Parameters            = uint32((*NVOS55_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS56Parameters            = uint32((*NVOS56_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS57Parameters            = uint32((*NVOS57_PARAMETERS)(nil).SizeBytes())
	SizeofNVOS64Parameters            = uint32((*NVOS64_PARAMETERS)(nil).SizeBytes())
)
