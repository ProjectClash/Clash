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

type ClassID uint32

func (id ClassID) String() string {
	return fmt.Sprintf("0x%08x", uint32(id))
}

func (id ClassID) IsRootClient() bool {
	switch id {
	case NV01_ROOT, NV01_ROOT_NON_PRIV, NV01_ROOT_CLIENT:
		return true
	default:
		return false
	}
}

const (
	NV01_ROOT                        = 0x00000000
	NV01_ROOT_NON_PRIV               = 0x00000001
	NV01_CONTEXT_DMA                 = 0x00000002
	NV01_EVENT                       = 0x00000005
	NV01_MEMORY_SYSTEM               = 0x0000003e
	NV01_MEMORY_LOCAL_PRIVILEGED     = 0x0000003f
	NV01_MEMORY_LOCAL_USER           = 0x00000040
	NV01_ROOT_CLIENT                 = 0x00000041
	NV_MEMORY_EXTENDED_USER          = 0x00000042
	NV01_MEMORY_VIRTUAL              = 0x00000070
	NV01_MEMORY_SYSTEM_OS_DESCRIPTOR = 0x00000071
	NV01_EVENT_OS_EVENT              = 0x00000079
	NV01_DEVICE_0                    = 0x00000080
	NV_SEMAPHORE_SURFACE             = 0x000000da
	RM_USER_SHARED_DATA              = 0x000000de
	NV_MEMORY_EXPORT                 = 0x000000e0
	NV_IMEX_SESSION                  = 0x000000f1
	NV_MEMORY_FABRIC                 = 0x000000f8
	NV_MEMORY_FABRIC_IMPORTED_REF    = 0x000000fb
	NV_MEMORY_MULTICAST_FABRIC       = 0x000000fd
	NV_MEMORY_MAPPER                 = 0x000000fe
	NV20_SUBDEVICE_0                 = 0x00002080
	NV2081_BINAPI                    = 0x00002081
	NV50_P2P                         = 0x0000503b
	NV50_THIRD_PARTY_P2P             = 0x0000503c
	NV50_MEMORY_VIRTUAL              = 0x000050a0
	GT200_DEBUGGER                   = 0x000083de
	MPS_COMPUTE                      = 0x0000900e
	FERMI_TWOD_A                     = 0x0000902d
	FERMI_CONTEXT_SHARE_A            = 0x00009067
	GF100_DISP_SW                    = 0x00009072
	GF100_ZBC_CLEAR                  = 0x00009096
	GF100_SUBDEVICE_INFOROM          = 0x000090e7
	GF100_PROFILER                   = 0x000090cc
	MAXWELL_PROFILER_DEVICE          = 0x0000b2cc
	NV_COUNTER_COLLECTION_UNIT       = 0x0000cbca
	GF100_SUBDEVICE_MASTER           = 0x000090e6
	FERMI_VASPACE_A                  = 0x000090f1
	KEPLER_CHANNEL_GROUP_A           = 0x0000a06c
	NVENC_SW_SESSION                 = 0x0000a0bc
	KEPLER_INLINE_TO_MEMORY_B        = 0x0000a140
	NVB8B0_VIDEO_DECODER             = 0x0000b8b0
	NVB8D1_VIDEO_NVJPG               = 0x0000b8d1
	NVB8FA_VIDEO_OFA                 = 0x0000b8fa
	VOLTA_USERMODE_A                 = 0x0000c361
	TURING_USERMODE_A                = 0x0000c461
	TURING_CHANNEL_GPFIFO_A          = 0x0000c46f
	NVC4B0_VIDEO_DECODER             = 0x0000c4b0
	NVC4B7_VIDEO_ENCODER             = 0x0000c4b7
	NVC4D1_VIDEO_NVJPG               = 0x0000c4d1
	AMPERE_CHANNEL_GPFIFO_A          = 0x0000c56f
	TURING_A                         = 0x0000c597
	TURING_DMA_COPY_A                = 0x0000c5b5
	TURING_COMPUTE_A                 = 0x0000c5c0
	HOPPER_USERMODE_A                = 0x0000c661
	AMPERE_A                         = 0x0000c697
	NVC6B0_VIDEO_DECODER             = 0x0000c6b0
	AMPERE_DMA_COPY_A                = 0x0000c6b5
	AMPERE_COMPUTE_A                 = 0x0000c6c0
	NVC6FA_VIDEO_OFA                 = 0x0000c6fa
	BLACKWELL_USERMODE_A             = 0x0000c761
	NVC7B0_VIDEO_DECODER             = 0x0000c7b0
	AMPERE_DMA_COPY_B                = 0x0000c7b5
	NVC7B7_VIDEO_ENCODER             = 0x0000c7b7
	AMPERE_COMPUTE_B                 = 0x0000c7c0
	NVC7FA_VIDEO_OFA                 = 0x0000c7fa
	HOPPER_CHANNEL_GPFIFO_A          = 0x0000c86f
	HOPPER_DMA_COPY_A                = 0x0000c8b5
	BLACKWELL_CHANNEL_GPFIFO_A       = 0x0000c96f
	ADA_A                            = 0x0000c997
	NVC9B0_VIDEO_DECODER             = 0x0000c9b0
	BLACKWELL_DMA_COPY_A             = 0x0000c9b5
	NVC9B7_VIDEO_ENCODER             = 0x0000c9b7
	ADA_COMPUTE_A                    = 0x0000c9c0
	NVC9D1_VIDEO_NVJPG               = 0x0000c9d1
	NVC9FA_VIDEO_OFA                 = 0x0000c9fa
	BLACKWELL_CHANNEL_GPFIFO_B       = 0x0000ca6f
	BLACKWELL_DMA_COPY_B             = 0x0000cab5
	NV_CONFIDENTIAL_COMPUTE          = 0x0000cb33
	HOPPER_A                         = 0x0000cb97
	HOPPER_SEC2_WORK_LAUNCH_A        = 0x0000cba2
	HOPPER_COMPUTE_A                 = 0x0000cbc0
	BLACKWELL_INLINE_TO_MEMORY_A     = 0x0000cd40
	BLACKWELL_A                      = 0x0000cd97
	NVCDB0_VIDEO_DECODER             = 0x0000cdb0
	BLACKWELL_COMPUTE_A              = 0x0000cdc0
	NVCDD1_VIDEO_NVJPG               = 0x0000cdd1
	NVCDFA_VIDEO_OFA                 = 0x0000cdfa
	BLACKWELL_B                      = 0x0000ce97
	NVCEB7_VIDEO_ENCODER             = 0x0000ceb7
	BLACKWELL_COMPUTE_B              = 0x0000cec0
	NVCFB7_VIDEO_ENCODER             = 0x0000cfb7
	NVD1B7_VIDEO_ENCODER             = 0x0000d1b7
)

const (
	NV01_NULL_OBJECT = 0x0
)

type NV2081_ALLOC_PARAMETERS struct {
	_        structs.HostLayout
	Reserved uint32
}

type NV0005_ALLOC_PARAMETERS struct {
	_             structs.HostLayout
	HParentClient Handle
	HSrcResource  Handle
	HClass        ClassID
	NotifyIndex   uint32
	Data          P64
}

const (
	NV20_SUBDEVICE_DIAG = 0x0000208f
)

const (
	NV_MEMORY_VIRTUAL_SYSMEM_DYNAMIC_HVASPACE = 0xffffffff
)

type NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS struct {
	_        structs.HostLayout
	Offset   uint64
	Limit    uint64
	HVASpace Handle
	Pad0     [4]byte
}

const (
	NV04_DISPLAY_COMMON = 0x00000073
)

type NV0080_ALLOC_PARAMETERS struct {
	_               structs.HostLayout
	DeviceID        uint32
	HClientShare    Handle
	HTargetClient   Handle
	HTargetDevice   Handle
	Flags           uint32
	Pad0            [4]byte
	VASpaceSize     uint64
	VAStartInternal uint64
	VALimitInternal uint64
	VAMode          uint32
	Pad1            [4]byte
}

type NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS struct {
	_                structs.HostLayout
	HSemaphoreMem    Handle
	HMaxSubmittedMem Handle
	flags            uint64
}

type NV2080_ALLOC_PARAMETERS struct {
	_           structs.HostLayout
	SubDeviceID uint32
}

type NV_CONTEXT_DMA_ALLOCATION_PARAMS struct {
	_          structs.HostLayout
	HSubDevice Handle
	Flags      uint32
	HMemory    Handle
	_          uint32
	Offset     uint64
	Limit      uint64
}

type NV_MEMORY_ALLOCATION_PARAMS struct {
	_             structs.HostLayout
	Owner         uint32
	Type          uint32
	Flags         uint32
	Width         uint32
	Height        uint32
	Pitch         int32
	Attr          uint32
	Attr2         uint32
	Format        uint32
	ComprCovg     uint32
	ZcullCovg     uint32
	_             uint32
	RangeLo       uint64
	RangeHi       uint64
	Size          uint64
	Alignment     uint64
	Offset        uint64
	Limit         uint64
	Address       P64
	CtagOffset    uint32
	HVASpace      Handle
	InternalFlags uint32
	Tag           uint32
}

type NV_MEMORY_ALLOCATION_PARAMS_V545 struct {
	_ structs.HostLayout
	NV_MEMORY_ALLOCATION_PARAMS
	NumaNode int32
	_        uint32
}

type NV503B_BAR1_P2P_DMA_INFO struct {
	_          structs.HostLayout
	DmaAddress uint64
	DmaSize    uint64
}

type NV503B_ALLOC_PARAMETERS struct {
	_                          structs.HostLayout
	HSubDevice                 Handle
	HPeerSubDevice             Handle
	SubDevicePeerIDMask        uint32
	PeerSubDevicePeerIDMask    uint32
	MailboxBar1Addr            uint64
	MailboxTotalSize           uint32
	Flags                      uint32
	SubDeviceEgmPeerIDMask     uint32
	PeerSubDeviceEgmPeerIDMask uint32
	L2pBar1P2PDmaInfo          NV503B_BAR1_P2P_DMA_INFO
	P2lBar1P2PDmaInfo          NV503B_BAR1_P2P_DMA_INFO
}

type NV503B_FABRIC_P2P_DMA_INFO struct {
	_   structs.HostLayout
	Gpa uint64
}

type NV503B_ALLOC_PARAMETERS_V590 struct {
	_ structs.HostLayout
	NV503B_ALLOC_PARAMETERS
	L2pFabricP2PInfo NV503B_FABRIC_P2P_DMA_INFO
	P2lFabricP2PInfo NV503B_FABRIC_P2P_DMA_INFO
}

type NV503C_ALLOC_PARAMETERS struct {
	_     structs.HostLayout
	Flags uint32
}

type NV83DE_ALLOC_PARAMETERS struct {
	_                        structs.HostLayout
	HDebuggerClient_Obsolete Handle
	HAppClient               Handle
	HClass3DObject           Handle
}

type NV_CTXSHARE_ALLOCATION_PARAMETERS struct {
	_        structs.HostLayout
	HVASpace Handle
	Flags    uint32
	SubctxID uint32
}

type NV_VASPACE_ALLOCATION_PARAMETERS struct {
	_               structs.HostLayout
	Index           uint32
	Flags           uint32
	VASize          uint64
	VAStartInternal uint64
	VALimitInternal uint64
	BigPageSize     uint32
	Pad0            [4]byte
	VABase          uint64
}

type NV_VASPACE_ALLOCATION_PARAMETERS_V580 struct {
	_ structs.HostLayout
	NV_VASPACE_ALLOCATION_PARAMETERS
	Pasid uint32
	Pad1  [4]byte
}

type NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS struct {
	_                           structs.HostLayout
	HObjectError                Handle
	HObjectECCError             Handle
	HVASpace                    Handle
	EngineType                  uint32
	BIsCallingContextVgpuPlugin uint8
	Pad0                        [3]byte
}

type NV_MEMORY_DESC_PARAMS struct {
	_            structs.HostLayout
	Base         uint64
	Size         uint64
	AddressSpace uint32
	CacheAttrib  uint32
}

type NV_BSP_ALLOCATION_PARAMETERS struct {
	_                         structs.HostLayout
	Size                      uint32
	ProhibitMultipleInstances uint32
	EngineInstance            uint32
}

type NV_MSENC_ALLOCATION_PARAMETERS struct {
	_                         structs.HostLayout
	Size                      uint32
	ProhibitMultipleInstances uint32
	EngineInstance            uint32
}

type NV_CHANNEL_ALLOC_PARAMS struct {
	_                   structs.HostLayout
	HObjectError        Handle
	HObjectBuffer       Handle
	GPFIFOOffset        uint64
	GPFIFOEntries       uint32
	Flags               uint32
	HContextShare       Handle
	HVASpace            Handle
	HUserdMemory        [NV_MAX_SUBDEVICES]Handle
	UserdOffset         [NV_MAX_SUBDEVICES]uint64
	EngineType          uint32
	CID                 uint32
	SubDeviceID         uint32
	HObjectECCError     Handle
	InstanceMem         NV_MEMORY_DESC_PARAMS
	UserdMem            NV_MEMORY_DESC_PARAMS
	RamfcMem            NV_MEMORY_DESC_PARAMS
	MthdbufMem          NV_MEMORY_DESC_PARAMS
	HPhysChannelGroup   Handle
	InternalFlags       uint32
	ErrorNotifierMem    NV_MEMORY_DESC_PARAMS
	ECCErrorNotifierMem NV_MEMORY_DESC_PARAMS
	ProcessID           uint32
	SubProcessID        uint32
	EncryptIv           [CC_CHAN_ALLOC_IV_SIZE_DWORD]uint32
	DecryptIv           [CC_CHAN_ALLOC_IV_SIZE_DWORD]uint32
	HmacNonce           [CC_CHAN_ALLOC_NONCE_SIZE_DWORD]uint32
}

type NV_CHANNEL_ALLOC_PARAMS_V570 struct {
	_ structs.HostLayout
	NV_CHANNEL_ALLOC_PARAMS
	TPCConfigID uint32
	_           uint32
}

type NV_CHANNEL_ALLOC_PARAMS_V610 struct {
	_                   structs.HostLayout
	HObjectError        Handle
	HObjectBuffer       Handle
	GPFIFOOffset        uint64
	GPFIFOEntries       uint32
	Flags               uint32
	HContextShare       Handle
	HVASpace            Handle
	HHandleVASpace      Handle
	HUserdMemory        [NV_MAX_SUBDEVICES]Handle
	_                   uint32
	UserdOffset         [NV_MAX_SUBDEVICES]uint64
	EngineType          uint32
	CID                 uint32
	SubDeviceID         uint32
	HObjectECCError     Handle
	InstanceMem         NV_MEMORY_DESC_PARAMS
	UserdMem            NV_MEMORY_DESC_PARAMS
	RamfcMem            NV_MEMORY_DESC_PARAMS
	MthdbufMem          NV_MEMORY_DESC_PARAMS
	HPhysChannelGroup   Handle
	InternalFlags       uint32
	ErrorNotifierMem    NV_MEMORY_DESC_PARAMS
	ECCErrorNotifierMem NV_MEMORY_DESC_PARAMS
	ProcessID           uint32
	SubProcessID        uint32
	EncryptIv           [CC_CHAN_ALLOC_IV_SIZE_DWORD]uint32
	DecryptIv           [CC_CHAN_ALLOC_IV_SIZE_DWORD]uint32
	HmacNonce           [CC_CHAN_ALLOC_NONCE_SIZE_DWORD]uint32
	TPCConfigID         uint32
	_                   uint32
}

type NVB0B5_ALLOCATION_PARAMETERS struct {
	_          structs.HostLayout
	Version    uint32
	EngineType uint32
}

type NV_GR_ALLOCATION_PARAMETERS struct {
	_       structs.HostLayout
	Version uint32
	Flags   uint32
	Size    uint32
	Caps    uint32
}

type NV_HOPPER_USERMODE_A_PARAMS struct {
	_           structs.HostLayout
	Bar1Mapping uint8
	Priv        uint8
}

type NV9072_ALLOCATION_PARAMETERS struct {
	_             structs.HostLayout
	LogicalHeadID uint32
	DisplayMask   uint32
	Caps          uint32
}

type NV00DE_ALLOC_PARAMETERS struct {
	_        structs.HostLayout
	Reserved uint32
}

type NV00DE_ALLOC_PARAMETERS_V545 struct {
	_              structs.HostLayout
	PolledDataMask uint64
}

type nv00f8Map struct {
	_       structs.HostLayout
	offset  uint64
	hVidMem Handle
	flags   uint32
}

const (
	NV_MEM_EXPORT_UUID_LEN     = 16
	NV_MEM_EXPORT_METADATA_LEN = 64
)

type NV_EXPORT_MEM_PACKET struct {
	_      structs.HostLayout
	UUID   [NV_MEM_EXPORT_UUID_LEN]uint8
	Opaque [16]uint8
}

type NV00E0_ALLOCATION_PARAMETERS struct {
	_                  structs.HostLayout
	IMEXChannel        uint32
	Packet             NV_EXPORT_MEM_PACKET
	NumMaxHandles      uint16
	Pad0               [2]byte
	Flags              uint32
	Metadata           [NV_MEM_EXPORT_METADATA_LEN]uint8
	DeviceInstanceMask uint32
	GIIDMasks          [NV_MAX_DEVICES]uint32
	NumCurHandles      uint16
	Pad1               [2]byte
}

type NV00F1_ALLOCATION_PARAMETERS struct {
	_             structs.HostLayout
	CapDescriptor uint64
	Flags         uint32
	Pad0          [4]byte
	POsEvent P64
	NodeID   uint16
	Pad1     [6]byte
}

type NV00F8_ALLOCATION_PARAMETERS struct {
	_          structs.HostLayout
	Alignment  uint64
	AllocSize  uint64
	PageSize   uint64
	AllocFlags uint32
	_          uint32
	Map        nv00f8Map
}

type NV00FB_ALLOCATION_PARAMETERS struct {
	_          structs.HostLayout
	ExportUUID [NV_MEM_EXPORT_UUID_LEN]uint8
	Index      uint16
	Pad0       [2]byte
	Flags      uint32
	ID         uint64
}

type HasPOsEvent interface {
	GetPOsEvent() P64
	SetPOsEvent(P64)
}

type NV00FD_ALLOCATION_PARAMETERS struct {
	_          structs.HostLayout
	Alignment  uint64
	AllocSize  uint64
	PageSize   uint32
	AllocFlags uint32
	NumGPUs    uint32
	_          uint32
	POsEvent P64
}

func (p *NV00FD_ALLOCATION_PARAMETERS) GetPOsEvent() P64 {
	return p.POsEvent
}

func (p *NV00FD_ALLOCATION_PARAMETERS) SetPOsEvent(posEvent P64) {
	p.POsEvent = posEvent
}

type NV00FD_ALLOCATION_PARAMETERS_V545 struct {
	_         structs.HostLayout
	ExpPacket NV_EXPORT_MEM_PACKET
	Index     uint16
	_         [6]byte
	NV00FD_ALLOCATION_PARAMETERS
}

type NV00FD_ALLOCATION_PARAMETERS_V590 struct {
	_          structs.HostLayout
	ExpPacket  NV_EXPORT_MEM_PACKET
	Index      uint16
	_          [6]byte
	Alignment  uint64
	AllocSize  uint64
	PageSize   uint64
	AllocFlags uint32
	NumGPUs    uint32
	POsEvent P64
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) GetPOsEvent() P64 {
	return p.POsEvent
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) SetPOsEvent(posEvent P64) {
	p.POsEvent = posEvent
}

type NV_MEMORY_MAPPER_ALLOCATION_PARAMS struct {
	_      structs.HostLayout
	unused uint8
}

type NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550 struct {
	_                 structs.HostLayout
	HSemaphoreSurface Handle
	MaxQueueSize      uint32
}

type NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555 struct {
	_ structs.HostLayout
	NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550
	HNotificationMemory Handle
	_                   uint32
	NotificationOffset  uint64
}

type NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS struct {
	_      structs.HostLayout
	Handle Handle
}

type NVA0BC_ALLOC_PARAMETERS struct {
	_           structs.HostLayout
	CodecType   uint32
	HResolution uint32
	VResolution uint32
	Version     uint32
	HMem        Handle
}

type NV_NVJPG_ALLOCATION_PARAMETERS struct {
	_                         structs.HostLayout
	Size                      uint32
	ProhibitMultipleInstances uint32
	EngineInstance            uint32
}

type NV_OFA_ALLOCATION_PARAMETERS struct {
	_                         structs.HostLayout
	Size                      uint32
	ProhibitMultipleInstances uint32
}

type NV_OFA_ALLOCATION_PARAMETERS_V545 struct {
	_ structs.HostLayout
	NV_OFA_ALLOCATION_PARAMETERS
	EngineInstance uint32
}

type NVB2CC_ALLOC_PARAMETERS struct {
	_              structs.HostLayout
	HClientTarget  Handle
	HContextTarget Handle
}
