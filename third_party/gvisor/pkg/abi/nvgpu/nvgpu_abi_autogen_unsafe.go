
package nvgpu

import (
    "github.com/metacubex/gvisor/pkg/gohacks"
    "github.com/metacubex/gvisor/pkg/hostarch"
    "github.com/metacubex/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

var _ marshal.Marshallable = (*ClassID)(nil)
var _ marshal.Marshallable = (*Handle)(nil)
var _ marshal.Marshallable = (*IoctlAllocOSEvent)(nil)
var _ marshal.Marshallable = (*IoctlCardInfo)(nil)
var _ marshal.Marshallable = (*IoctlExportToDMABufFD)(nil)
var _ marshal.Marshallable = (*IoctlExportToDMABufFD_V570)(nil)
var _ marshal.Marshallable = (*IoctlExportToDMABufFD_V580)(nil)
var _ marshal.Marshallable = (*IoctlFreeOSEvent)(nil)
var _ marshal.Marshallable = (*IoctlNVOS02ParametersWithFD)(nil)
var _ marshal.Marshallable = (*IoctlNVOS33ParametersWithFD)(nil)
var _ marshal.Marshallable = (*IoctlRegisterFD)(nil)
var _ marshal.Marshallable = (*IoctlSysParams)(nil)
var _ marshal.Marshallable = (*IoctlWaitOpenComplete)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_GPU_ATTACH_IDS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_GPU_GET_ID_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*NV0005_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV0080_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_GET_CAPS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV0080_CTRL_GR_ROUTE_INFO)(nil)
var _ marshal.Marshallable = (*NV00DE_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00DE_ALLOC_PARAMETERS_V545)(nil)
var _ marshal.Marshallable = (*NV00E0_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00F1_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00F8_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00FB_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00FD_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV00FD_ALLOCATION_PARAMETERS_V545)(nil)
var _ marshal.Marshallable = (*NV00FD_ALLOCATION_PARAMETERS_V590)(nil)
var _ marshal.Marshallable = (*NV00FD_CTRL_ATTACH_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2080_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_GPU_REG_OP)(nil)
var _ marshal.Marshallable = (*NV2080_CTRL_GR_GET_INFO_PARAMS)(nil)
var _ marshal.Marshallable = (*NV2081_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS)(nil)
var _ marshal.Marshallable = (*NV503B_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV503B_ALLOC_PARAMETERS_V590)(nil)
var _ marshal.Marshallable = (*NV503B_BAR1_P2P_DMA_INFO)(nil)
var _ marshal.Marshallable = (*NV503B_FABRIC_P2P_DMA_INFO)(nil)
var _ marshal.Marshallable = (*NV503C_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV503C_CTRL_REGISTER_VA_SPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*NV83DE_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV9072_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVA0BC_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVB0B5_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVB2CC_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS00_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS02_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS21_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS30_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS32_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS33_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS34_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS39_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS46_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS46_PARAMETERS_V580)(nil)
var _ marshal.Marshallable = (*NVOS47_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS47_PARAMETERS_V550)(nil)
var _ marshal.Marshallable = (*NVOS54_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS55_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS56_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS57_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVOS64_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NVXXXX_CTRL_XXX_INFO)(nil)
var _ marshal.Marshallable = (*NV_BSP_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_ALLOC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_ALLOC_PARAMS_V570)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_ALLOC_PARAMS_V610)(nil)
var _ marshal.Marshallable = (*NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CONTEXT_DMA_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_CTXSHARE_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_EXPORT_MEM_PACKET)(nil)
var _ marshal.Marshallable = (*NV_GR_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_HOPPER_USERMODE_A_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_ALLOCATION_PARAMS_V545)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_DESC_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_MAPPER_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555)(nil)
var _ marshal.Marshallable = (*NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*NV_MSENC_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_NVJPG_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_OFA_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_OFA_ALLOCATION_PARAMETERS_V545)(nil)
var _ marshal.Marshallable = (*NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_VASPACE_ALLOCATION_PARAMETERS)(nil)
var _ marshal.Marshallable = (*NV_VASPACE_ALLOCATION_PARAMETERS_V580)(nil)
var _ marshal.Marshallable = (*NvUUID)(nil)
var _ marshal.Marshallable = (*NvxxxCtrlXxxGetInfoParams)(nil)
var _ marshal.Marshallable = (*P64)(nil)
var _ marshal.Marshallable = (*PCIInfo)(nil)
var _ marshal.Marshallable = (*RMAPIVersion)(nil)
var _ marshal.Marshallable = (*RS_ACCESS_MASK)(nil)
var _ marshal.Marshallable = (*RS_SHARE_POLICY)(nil)
var _ marshal.Marshallable = (*RmapiParamNvU32List)(nil)
var _ marshal.Marshallable = (*UVM_ALLOC_SEMAPHORE_POOL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_CREATE_EXTERNAL_RANGE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_CREATE_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DESTROY_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DISABLE_PEER_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_DISABLE_READ_DUPLICATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_ENABLE_PEER_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_ENABLE_READ_DUPLICATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_FREE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_FREE_PARAMS_V590)(nil)
var _ marshal.Marshallable = (*UVM_INITIALIZE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_EXTERNAL_ALLOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_MIGRATE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MIGRATE_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_MIGRATE_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_MM_INITIALIZE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_PAGEABLE_MEM_ACCESS_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_CHANNEL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_REGISTER_GPU_VASPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_SET_ACCESSED_BY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_SET_PREFERRED_LOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_SET_PREFERRED_LOCATION_PARAMS_V550)(nil)
var _ marshal.Marshallable = (*UVM_SET_RANGE_GROUP_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNMAP_EXTERNAL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_CHANNEL_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_CHANNEL_PARAMS_V590)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_GPU_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNREGISTER_GPU_VASPACE_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNSET_ACCESSED_BY_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_UNSET_PREFERRED_LOCATION_PARAMS)(nil)
var _ marshal.Marshallable = (*UVM_VALIDATE_VA_RANGE_PARAMS)(nil)
var _ marshal.Marshallable = (*UvmGpuMappingAttributes)(nil)
var _ marshal.Marshallable = (*nv00f8Map)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (id *ClassID) SizeBytes() int {
    return 4
}

func (id *ClassID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*id))
    return dst[4:]
}

func (id *ClassID) UnmarshalBytes(src []byte) []byte {
    *id = ClassID(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (id *ClassID) Packed() bool {
    return true
}

func (id *ClassID) MarshalUnsafe(dst []byte) []byte {
    size := id.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(id), uintptr(size))
    return dst[size:]
}

func (id *ClassID) UnmarshalUnsafe(src []byte) []byte {
    size := id.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(id), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (id *ClassID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(id)))
    hdr.Len = id.SizeBytes()
    hdr.Cap = id.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(id)
    return length, err
}

func (id *ClassID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return id.CopyOutN(cc, addr, id.SizeBytes())
}

func (id *ClassID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(id)))
    hdr.Len = id.SizeBytes()
    hdr.Cap = id.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(id)
    return length, err
}

func (id *ClassID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return id.CopyInN(cc, addr, id.SizeBytes())
}

func (id *ClassID) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(id)))
    hdr.Len = id.SizeBytes()
    hdr.Cap = id.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(id)
    return int64(length), err
}

func (n *NV0005_ALLOC_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NV0005_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HParentClient.MarshalUnsafe(dst)
    dst = n.HSrcResource.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NotifyIndex))
    dst = dst[4:]
    dst = n.Data.MarshalUnsafe(dst)
    return dst
}

func (n *NV0005_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HParentClient.UnmarshalUnsafe(src)
    src = n.HSrcResource.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    n.NotifyIndex = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Data.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0005_ALLOC_PARAMETERS) Packed() bool {
    return n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed()
}

func (n *NV0005_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0005_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0005_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0005_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0005_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0005_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0005_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Data.Packed() && n.HClass.Packed() && n.HParentClient.Packed() && n.HSrcResource.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0080_ALLOC_PARAMETERS) SizeBytes() int {
    return 36 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (n *NV0080_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DeviceID))
    dst = dst[4:]
    dst = n.HClientShare.MarshalUnsafe(dst)
    dst = n.HTargetClient.MarshalUnsafe(dst)
    dst = n.HTargetDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VASpaceSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VAStartInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VALimitInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.VAMode))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV0080_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.DeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HClientShare.UnmarshalUnsafe(src)
    src = n.HTargetClient.UnmarshalUnsafe(src)
    src = n.HTargetDevice.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.VASpaceSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VAStartInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VALimitInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VAMode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_ALLOC_PARAMETERS) Packed() bool {
    return n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed()
}

func (n *NV0080_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0080_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0080_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0080_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0080_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClientShare.Packed() && n.HTargetClient.Packed() && n.HTargetDevice.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00DE_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

func (n *NV00DE_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Reserved))
    dst = dst[4:]
    return dst
}

func (n *NV00DE_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Reserved = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00DE_ALLOC_PARAMETERS) Packed() bool {
    return true
}

func (n *NV00DE_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV00DE_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV00DE_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00DE_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00DE_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00DE_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00DE_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) SizeBytes() int {
    return 8
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.PolledDataMask))
    dst = dst[8:]
    return dst
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) UnmarshalBytes(src []byte) []byte {
    n.PolledDataMask = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00DE_ALLOC_PARAMETERS_V545) Packed() bool {
    return true
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00DE_ALLOC_PARAMETERS_V545) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00E0_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 16 +
        (*NV_EXPORT_MEM_PACKET)(nil).SizeBytes() +
        1*2 +
        1*NV_MEM_EXPORT_METADATA_LEN +
        4*NV_MAX_DEVICES +
        1*2
}

func (n *NV00E0_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.IMEXChannel))
    dst = dst[4:]
    dst = n.Packet.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.NumMaxHandles))
    dst = dst[2:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < NV_MEM_EXPORT_METADATA_LEN; idx++ {
        dst[0] = byte(n.Metadata[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DeviceInstanceMask))
    dst = dst[4:]
    for idx := 0; idx < NV_MAX_DEVICES; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GIIDMasks[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.NumCurHandles))
    dst = dst[2:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV00E0_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.IMEXChannel = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Packet.UnmarshalUnsafe(src)
    n.NumMaxHandles = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 2; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV_MEM_EXPORT_METADATA_LEN; idx++ {
        n.Metadata[idx] = uint8(src[0])
        src = src[1:]
    }
    n.DeviceInstanceMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV_MAX_DEVICES; idx++ {
        n.GIIDMasks[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    n.NumCurHandles = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 2; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00E0_ALLOCATION_PARAMETERS) Packed() bool {
    return n.Packet.Packed()
}

func (n *NV00E0_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Packet.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV00E0_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Packet.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV00E0_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Packet.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00E0_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00E0_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Packet.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00E0_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00E0_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Packet.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00F1_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 14 +
        1*4 +
        (*P64)(nil).SizeBytes() +
        1*6
}

func (n *NV00F1_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.CapDescriptor))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.POsEvent.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.NodeID))
    dst = dst[2:]
    for idx := 0; idx < 6; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV00F1_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.CapDescriptor = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.POsEvent.UnmarshalUnsafe(src)
    n.NodeID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 6; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00F1_ALLOCATION_PARAMETERS) Packed() bool {
    return n.POsEvent.Packed()
}

func (n *NV00F1_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.POsEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV00F1_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.POsEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV00F1_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.POsEvent.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00F1_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00F1_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.POsEvent.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00F1_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00F1_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.POsEvent.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00F8_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 32 +
        (*nv00f8Map)(nil).SizeBytes()
}

func (n *NV00F8_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.AllocSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.PageSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.AllocFlags))
    dst = dst[4:]
    dst = dst[4:]
    dst = n.Map.MarshalUnsafe(dst)
    return dst
}

func (n *NV00F8_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AllocSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.PageSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AllocFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    src = n.Map.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00F8_ALLOCATION_PARAMETERS) Packed() bool {
    return n.Map.Packed()
}

func (n *NV00F8_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Map.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV00F8_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Map.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV00F8_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Map.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00F8_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00F8_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Map.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00F8_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00F8_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Map.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00FB_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 14 +
        1*NV_MEM_EXPORT_UUID_LEN +
        1*2
}

func (n *NV00FB_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < NV_MEM_EXPORT_UUID_LEN; idx++ {
        dst[0] = byte(n.ExportUUID[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Index))
    dst = dst[2:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.ID))
    dst = dst[8:]
    return dst
}

func (n *NV00FB_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < NV_MEM_EXPORT_UUID_LEN; idx++ {
        n.ExportUUID[idx] = uint8(src[0])
        src = src[1:]
    }
    n.Index = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 2; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00FB_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV00FB_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV00FB_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV00FB_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00FB_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00FB_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00FB_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00FB_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (p *NV00FD_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 32 +
        (*P64)(nil).SizeBytes()
}

func (p *NV00FD_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.AllocSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.PageSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.AllocFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumGPUs))
    dst = dst[4:]
    dst = dst[4:]
    dst = p.POsEvent.MarshalUnsafe(dst)
    return dst
}

func (p *NV00FD_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    p.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.AllocSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.PageSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.AllocFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.NumGPUs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    src = p.POsEvent.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV00FD_ALLOCATION_PARAMETERS) Packed() bool {
    return p.POsEvent.Packed()
}

func (p *NV00FD_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if p.POsEvent.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV00FD_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if p.POsEvent.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV00FD_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.POsEvent.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV00FD_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV00FD_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.POsEvent.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV00FD_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV00FD_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !p.POsEvent.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) SizeBytes() int {
    return 2 +
        (*NV_EXPORT_MEM_PACKET)(nil).SizeBytes() +
        1*6 +
        (*NV00FD_ALLOCATION_PARAMETERS)(nil).SizeBytes()
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) MarshalBytes(dst []byte) []byte {
    dst = n.ExpPacket.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Index))
    dst = dst[2:]
    dst = dst[1*(6):]
    dst = n.NV00FD_ALLOCATION_PARAMETERS.MarshalUnsafe(dst)
    return dst
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) UnmarshalBytes(src []byte) []byte {
    src = n.ExpPacket.UnmarshalUnsafe(src)
    n.Index = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(6):]
    src = n.NV00FD_ALLOCATION_PARAMETERS.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00FD_ALLOCATION_PARAMETERS_V545) Packed() bool {
    return n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed()
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) MarshalUnsafe(dst []byte) []byte {
    if n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) UnmarshalUnsafe(src []byte) []byte {
    if n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00FD_ALLOCATION_PARAMETERS_V545) WriteTo(writer io.Writer) (int64, error) {
    if !n.ExpPacket.Packed() && n.NV00FD_ALLOCATION_PARAMETERS.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) SizeBytes() int {
    return 34 +
        (*NV_EXPORT_MEM_PACKET)(nil).SizeBytes() +
        1*6 +
        (*P64)(nil).SizeBytes()
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) MarshalBytes(dst []byte) []byte {
    dst = p.ExpPacket.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.Index))
    dst = dst[2:]
    dst = dst[1*(6):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.AllocSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.PageSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.AllocFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumGPUs))
    dst = dst[4:]
    dst = p.POsEvent.MarshalUnsafe(dst)
    return dst
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) UnmarshalBytes(src []byte) []byte {
    src = p.ExpPacket.UnmarshalUnsafe(src)
    p.Index = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(6):]
    p.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.AllocSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.PageSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.AllocFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.NumGPUs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.POsEvent.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV00FD_ALLOCATION_PARAMETERS_V590) Packed() bool {
    return p.ExpPacket.Packed() && p.POsEvent.Packed()
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) MarshalUnsafe(dst []byte) []byte {
    if p.ExpPacket.Packed() && p.POsEvent.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) UnmarshalUnsafe(src []byte) []byte {
    if p.ExpPacket.Packed() && p.POsEvent.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.ExpPacket.Packed() && p.POsEvent.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.ExpPacket.Packed() && p.POsEvent.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV00FD_ALLOCATION_PARAMETERS_V590) WriteTo(writer io.Writer) (int64, error) {
    if !p.ExpPacket.Packed() && p.POsEvent.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (n *NV2080_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

func (n *NV2080_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceID))
    dst = dst[4:]
    return dst
}

func (n *NV2080_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.SubDeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_ALLOC_PARAMETERS) Packed() bool {
    return true
}

func (n *NV2080_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV2080_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV2080_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV2080_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV2080_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV2081_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

func (n *NV2081_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Reserved))
    dst = dst[4:]
    return dst
}

func (n *NV2081_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Reserved = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2081_ALLOC_PARAMETERS) Packed() bool {
    return true
}

func (n *NV2081_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV2081_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV2081_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2081_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV2081_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2081_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV2081_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV503B_ALLOC_PARAMETERS) SizeBytes() int {
    return 32 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*NV503B_BAR1_P2P_DMA_INFO)(nil).SizeBytes() +
        (*NV503B_BAR1_P2P_DMA_INFO)(nil).SizeBytes()
}

func (n *NV503B_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HSubDevice.MarshalUnsafe(dst)
    dst = n.HPeerSubDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDevicePeerIDMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PeerSubDevicePeerIDMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.MailboxBar1Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.MailboxTotalSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceEgmPeerIDMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PeerSubDeviceEgmPeerIDMask))
    dst = dst[4:]
    dst = n.L2pBar1P2PDmaInfo.MarshalUnsafe(dst)
    dst = n.P2lBar1P2PDmaInfo.MarshalUnsafe(dst)
    return dst
}

func (n *NV503B_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HSubDevice.UnmarshalUnsafe(src)
    src = n.HPeerSubDevice.UnmarshalUnsafe(src)
    n.SubDevicePeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.PeerSubDevicePeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.MailboxBar1Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.MailboxTotalSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceEgmPeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.PeerSubDeviceEgmPeerIDMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.L2pBar1P2PDmaInfo.UnmarshalUnsafe(src)
    src = n.P2lBar1P2PDmaInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503B_ALLOC_PARAMETERS) Packed() bool {
    return n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed()
}

func (n *NV503B_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV503B_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV503B_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV503B_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV503B_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HPeerSubDevice.Packed() && n.HSubDevice.Packed() && n.L2pBar1P2PDmaInfo.Packed() && n.P2lBar1P2PDmaInfo.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV503B_ALLOC_PARAMETERS_V590) SizeBytes() int {
    return 0 +
        (*NV503B_ALLOC_PARAMETERS)(nil).SizeBytes() +
        (*NV503B_FABRIC_P2P_DMA_INFO)(nil).SizeBytes() +
        (*NV503B_FABRIC_P2P_DMA_INFO)(nil).SizeBytes()
}

func (n *NV503B_ALLOC_PARAMETERS_V590) MarshalBytes(dst []byte) []byte {
    dst = n.NV503B_ALLOC_PARAMETERS.MarshalUnsafe(dst)
    dst = n.L2pFabricP2PInfo.MarshalUnsafe(dst)
    dst = n.P2lFabricP2PInfo.MarshalUnsafe(dst)
    return dst
}

func (n *NV503B_ALLOC_PARAMETERS_V590) UnmarshalBytes(src []byte) []byte {
    src = n.NV503B_ALLOC_PARAMETERS.UnmarshalUnsafe(src)
    src = n.L2pFabricP2PInfo.UnmarshalUnsafe(src)
    src = n.P2lFabricP2PInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503B_ALLOC_PARAMETERS_V590) Packed() bool {
    return n.L2pFabricP2PInfo.Packed() && n.NV503B_ALLOC_PARAMETERS.Packed() && n.P2lFabricP2PInfo.Packed()
}

func (n *NV503B_ALLOC_PARAMETERS_V590) MarshalUnsafe(dst []byte) []byte {
    if n.L2pFabricP2PInfo.Packed() && n.NV503B_ALLOC_PARAMETERS.Packed() && n.P2lFabricP2PInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV503B_ALLOC_PARAMETERS_V590) UnmarshalUnsafe(src []byte) []byte {
    if n.L2pFabricP2PInfo.Packed() && n.NV503B_ALLOC_PARAMETERS.Packed() && n.P2lFabricP2PInfo.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV503B_ALLOC_PARAMETERS_V590) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.L2pFabricP2PInfo.Packed() && n.NV503B_ALLOC_PARAMETERS.Packed() && n.P2lFabricP2PInfo.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_ALLOC_PARAMETERS_V590) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV503B_ALLOC_PARAMETERS_V590) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.L2pFabricP2PInfo.Packed() && n.NV503B_ALLOC_PARAMETERS.Packed() && n.P2lFabricP2PInfo.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_ALLOC_PARAMETERS_V590) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV503B_ALLOC_PARAMETERS_V590) WriteTo(writer io.Writer) (int64, error) {
    if !n.L2pFabricP2PInfo.Packed() && n.NV503B_ALLOC_PARAMETERS.Packed() && n.P2lFabricP2PInfo.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV503B_BAR1_P2P_DMA_INFO) SizeBytes() int {
    return 16
}

func (n *NV503B_BAR1_P2P_DMA_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaSize))
    dst = dst[8:]
    return dst
}

func (n *NV503B_BAR1_P2P_DMA_INFO) UnmarshalBytes(src []byte) []byte {
    n.DmaAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.DmaSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503B_BAR1_P2P_DMA_INFO) Packed() bool {
    return true
}

func (n *NV503B_BAR1_P2P_DMA_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV503B_BAR1_P2P_DMA_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV503B_BAR1_P2P_DMA_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_BAR1_P2P_DMA_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV503B_BAR1_P2P_DMA_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_BAR1_P2P_DMA_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV503B_BAR1_P2P_DMA_INFO) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) SizeBytes() int {
    return 8
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Gpa))
    dst = dst[8:]
    return dst
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) UnmarshalBytes(src []byte) []byte {
    n.Gpa = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503B_FABRIC_P2P_DMA_INFO) Packed() bool {
    return true
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV503B_FABRIC_P2P_DMA_INFO) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV503C_ALLOC_PARAMETERS) SizeBytes() int {
    return 4
}

func (n *NV503C_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    return dst
}

func (n *NV503C_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503C_ALLOC_PARAMETERS) Packed() bool {
    return true
}

func (n *NV503C_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV503C_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV503C_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503C_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV503C_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503C_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV503C_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV83DE_ALLOC_PARAMETERS) SizeBytes() int {
    return 0 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NV83DE_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HDebuggerClient_Obsolete.MarshalUnsafe(dst)
    dst = n.HAppClient.MarshalUnsafe(dst)
    dst = n.HClass3DObject.MarshalUnsafe(dst)
    return dst
}

func (n *NV83DE_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HDebuggerClient_Obsolete.UnmarshalUnsafe(src)
    src = n.HAppClient.UnmarshalUnsafe(src)
    src = n.HClass3DObject.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV83DE_ALLOC_PARAMETERS) Packed() bool {
    return n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed()
}

func (n *NV83DE_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV83DE_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV83DE_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV83DE_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV83DE_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV83DE_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV83DE_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HAppClient.Packed() && n.HClass3DObject.Packed() && n.HDebuggerClient_Obsolete.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV9072_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

func (n *NV9072_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.LogicalHeadID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DisplayMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Caps))
    dst = dst[4:]
    return dst
}

func (n *NV9072_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.LogicalHeadID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.DisplayMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Caps = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV9072_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV9072_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV9072_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV9072_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV9072_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV9072_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV9072_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV9072_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVA0BC_ALLOC_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes()
}

func (n *NVA0BC_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CodecType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HResolution))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.VResolution))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Version))
    dst = dst[4:]
    dst = n.HMem.MarshalUnsafe(dst)
    return dst
}

func (n *NVA0BC_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.CodecType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.HResolution = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.VResolution = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HMem.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVA0BC_ALLOC_PARAMETERS) Packed() bool {
    return n.HMem.Packed()
}

func (n *NVA0BC_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVA0BC_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVA0BC_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVA0BC_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVA0BC_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVA0BC_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVA0BC_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HMem.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 8
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    return dst
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVB0B5_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVB0B5_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVB2CC_ALLOC_PARAMETERS) SizeBytes() int {
    return 0 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NVB2CC_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClientTarget.MarshalUnsafe(dst)
    dst = n.HContextTarget.MarshalUnsafe(dst)
    return dst
}

func (n *NVB2CC_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClientTarget.UnmarshalUnsafe(src)
    src = n.HContextTarget.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVB2CC_ALLOC_PARAMETERS) Packed() bool {
    return n.HClientTarget.Packed() && n.HContextTarget.Packed()
}

func (n *NVB2CC_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClientTarget.Packed() && n.HContextTarget.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVB2CC_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClientTarget.Packed() && n.HContextTarget.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVB2CC_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClientTarget.Packed() && n.HContextTarget.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVB2CC_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVB2CC_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClientTarget.Packed() && n.HContextTarget.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVB2CC_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVB2CC_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClientTarget.Packed() && n.HContextTarget.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProhibitMultipleInstances))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineInstance))
    dst = dst[4:]
    return dst
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ProhibitMultipleInstances = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_BSP_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_BSP_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CHANNEL_ALLOC_PARAMS) SizeBytes() int {
    return 40 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV_MAX_SUBDEVICES +
        8*NV_MAX_SUBDEVICES +
        (*Handle)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        4*CC_CHAN_ALLOC_IV_SIZE_DWORD +
        4*CC_CHAN_ALLOC_IV_SIZE_DWORD +
        4*CC_CHAN_ALLOC_NONCE_SIZE_DWORD
}

func (n *NV_CHANNEL_ALLOC_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectError.MarshalUnsafe(dst)
    dst = n.HObjectBuffer.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.GPFIFOOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GPFIFOEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.HContextShare.MarshalUnsafe(dst)
    dst = n.HVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        dst = n.HUserdMemory[idx].MarshalUnsafe(dst)
    }
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.UserdOffset[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceID))
    dst = dst[4:]
    dst = n.HObjectECCError.MarshalUnsafe(dst)
    dst = n.InstanceMem.MarshalUnsafe(dst)
    dst = n.UserdMem.MarshalUnsafe(dst)
    dst = n.RamfcMem.MarshalUnsafe(dst)
    dst = n.MthdbufMem.MarshalUnsafe(dst)
    dst = n.HPhysChannelGroup.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.InternalFlags))
    dst = dst[4:]
    dst = n.ErrorNotifierMem.MarshalUnsafe(dst)
    dst = n.ECCErrorNotifierMem.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProcessID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubProcessID))
    dst = dst[4:]
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EncryptIv[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DecryptIv[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HmacNonce[idx]))
        dst = dst[4:]
    }
    return dst
}

func (n *NV_CHANNEL_ALLOC_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectError.UnmarshalUnsafe(src)
    src = n.HObjectBuffer.UnmarshalUnsafe(src)
    n.GPFIFOOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.GPFIFOEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HContextShare.UnmarshalUnsafe(src)
    src = n.HVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        src = n.HUserdMemory[idx].UnmarshalUnsafe(src)
    }
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        n.UserdOffset[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.CID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HObjectECCError.UnmarshalUnsafe(src)
    src = n.InstanceMem.UnmarshalUnsafe(src)
    src = n.UserdMem.UnmarshalUnsafe(src)
    src = n.RamfcMem.UnmarshalUnsafe(src)
    src = n.MthdbufMem.UnmarshalUnsafe(src)
    src = n.HPhysChannelGroup.UnmarshalUnsafe(src)
    n.InternalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.ErrorNotifierMem.UnmarshalUnsafe(src)
    src = n.ECCErrorNotifierMem.UnmarshalUnsafe(src)
    n.ProcessID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubProcessID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        n.EncryptIv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        n.DecryptIv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; idx++ {
        n.HmacNonce[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_ALLOC_PARAMS) Packed() bool {
    return n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed()
}

func (n *NV_CHANNEL_ALLOC_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CHANNEL_ALLOC_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CHANNEL_ALLOC_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_ALLOC_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_ALLOC_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_ALLOC_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_ALLOC_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) SizeBytes() int {
    return 8 +
        (*NV_CHANNEL_ALLOC_PARAMS)(nil).SizeBytes()
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) MarshalBytes(dst []byte) []byte {
    dst = n.NV_CHANNEL_ALLOC_PARAMS.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.TPCConfigID))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) UnmarshalBytes(src []byte) []byte {
    src = n.NV_CHANNEL_ALLOC_PARAMS.UnmarshalUnsafe(src)
    n.TPCConfigID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_ALLOC_PARAMS_V570) Packed() bool {
    return n.NV_CHANNEL_ALLOC_PARAMS.Packed()
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) MarshalUnsafe(dst []byte) []byte {
    if n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) UnmarshalUnsafe(src []byte) []byte {
    if n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V570) WriteTo(writer io.Writer) (int64, error) {
    if !n.NV_CHANNEL_ALLOC_PARAMS.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) SizeBytes() int {
    return 52 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV_MAX_SUBDEVICES +
        8*NV_MAX_SUBDEVICES +
        (*Handle)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        (*NV_MEMORY_DESC_PARAMS)(nil).SizeBytes() +
        4*CC_CHAN_ALLOC_IV_SIZE_DWORD +
        4*CC_CHAN_ALLOC_IV_SIZE_DWORD +
        4*CC_CHAN_ALLOC_NONCE_SIZE_DWORD
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectError.MarshalUnsafe(dst)
    dst = n.HObjectBuffer.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.GPFIFOOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GPFIFOEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.HContextShare.MarshalUnsafe(dst)
    dst = n.HVASpace.MarshalUnsafe(dst)
    dst = n.HHandleVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        dst = n.HUserdMemory[idx].MarshalUnsafe(dst)
    }
    dst = dst[4:]
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.UserdOffset[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceID))
    dst = dst[4:]
    dst = n.HObjectECCError.MarshalUnsafe(dst)
    dst = n.InstanceMem.MarshalUnsafe(dst)
    dst = n.UserdMem.MarshalUnsafe(dst)
    dst = n.RamfcMem.MarshalUnsafe(dst)
    dst = n.MthdbufMem.MarshalUnsafe(dst)
    dst = n.HPhysChannelGroup.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.InternalFlags))
    dst = dst[4:]
    dst = n.ErrorNotifierMem.MarshalUnsafe(dst)
    dst = n.ECCErrorNotifierMem.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProcessID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubProcessID))
    dst = dst[4:]
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EncryptIv[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DecryptIv[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.HmacNonce[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.TPCConfigID))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectError.UnmarshalUnsafe(src)
    src = n.HObjectBuffer.UnmarshalUnsafe(src)
    n.GPFIFOOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.GPFIFOEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HContextShare.UnmarshalUnsafe(src)
    src = n.HVASpace.UnmarshalUnsafe(src)
    src = n.HHandleVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        src = n.HUserdMemory[idx].UnmarshalUnsafe(src)
    }
    src = src[4:]
    for idx := 0; idx < NV_MAX_SUBDEVICES; idx++ {
        n.UserdOffset[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.CID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HObjectECCError.UnmarshalUnsafe(src)
    src = n.InstanceMem.UnmarshalUnsafe(src)
    src = n.UserdMem.UnmarshalUnsafe(src)
    src = n.RamfcMem.UnmarshalUnsafe(src)
    src = n.MthdbufMem.UnmarshalUnsafe(src)
    src = n.HPhysChannelGroup.UnmarshalUnsafe(src)
    n.InternalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.ErrorNotifierMem.UnmarshalUnsafe(src)
    src = n.ECCErrorNotifierMem.UnmarshalUnsafe(src)
    n.ProcessID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubProcessID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        n.EncryptIv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_IV_SIZE_DWORD; idx++ {
        n.DecryptIv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < CC_CHAN_ALLOC_NONCE_SIZE_DWORD; idx++ {
        n.HmacNonce[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    n.TPCConfigID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_ALLOC_PARAMS_V610) Packed() bool {
    return n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HHandleVASpace.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed()
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) MarshalUnsafe(dst []byte) []byte {
    if n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HHandleVASpace.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) UnmarshalUnsafe(src []byte) []byte {
    if n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HHandleVASpace.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HHandleVASpace.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HHandleVASpace.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_ALLOC_PARAMS_V610) WriteTo(writer io.Writer) (int64, error) {
    if !n.ECCErrorNotifierMem.Packed() && n.ErrorNotifierMem.Packed() && n.HContextShare.Packed() && n.HHandleVASpace.Packed() && n.HObjectBuffer.Packed() && n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HPhysChannelGroup.Packed() && n.HUserdMemory[0].Packed() && n.HVASpace.Packed() && n.InstanceMem.Packed() && n.MthdbufMem.Packed() && n.RamfcMem.Packed() && n.UserdMem.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 5 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*3
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectError.MarshalUnsafe(dst)
    dst = n.HObjectECCError.MarshalUnsafe(dst)
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineType))
    dst = dst[4:]
    dst[0] = byte(n.BIsCallingContextVgpuPlugin)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectError.UnmarshalUnsafe(src)
    src = n.HObjectECCError.UnmarshalUnsafe(src)
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.EngineType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.BIsCallingContextVgpuPlugin = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) Packed() bool {
    return n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed()
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectECCError.Packed() && n.HObjectError.Packed() && n.HVASpace.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) SizeBytes() int {
    return 0 +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.Handle.MarshalUnsafe(dst)
    return dst
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.Handle.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) Packed() bool {
    return n.Handle.Packed()
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.Handle.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.Handle.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Handle.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Handle.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Handle.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HSubDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.HMemory.MarshalUnsafe(dst)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    return dst
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HSubDevice.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HMemory.UnmarshalUnsafe(src)
    src = src[4:]
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) Packed() bool {
    return n.HMemory.Packed() && n.HSubDevice.Packed()
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HMemory.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HMemory.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMemory.Packed() && n.HSubDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMemory.Packed() && n.HSubDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CONTEXT_DMA_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HMemory.Packed() && n.HSubDevice.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubctxID))
    dst = dst[4:]
    return dst
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubctxID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) Packed() bool {
    return n.HVASpace.Packed()
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_CTXSHARE_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HVASpace.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_EXPORT_MEM_PACKET) SizeBytes() int {
    return 0 +
        1*NV_MEM_EXPORT_UUID_LEN +
        1*16
}

func (n *NV_EXPORT_MEM_PACKET) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < NV_MEM_EXPORT_UUID_LEN; idx++ {
        dst[0] = byte(n.UUID[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(n.Opaque[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV_EXPORT_MEM_PACKET) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < NV_MEM_EXPORT_UUID_LEN; idx++ {
        n.UUID[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 16; idx++ {
        n.Opaque[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_EXPORT_MEM_PACKET) Packed() bool {
    return true
}

func (n *NV_EXPORT_MEM_PACKET) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_EXPORT_MEM_PACKET) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_EXPORT_MEM_PACKET) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_EXPORT_MEM_PACKET) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_EXPORT_MEM_PACKET) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_EXPORT_MEM_PACKET) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_EXPORT_MEM_PACKET) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_GR_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 16
}

func (n *NV_GR_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Caps))
    dst = dst[4:]
    return dst
}

func (n *NV_GR_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Caps = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_GR_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV_GR_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_GR_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_GR_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_GR_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_GR_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_GR_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_GR_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) SizeBytes() int {
    return 2
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.Bar1Mapping)
    dst = dst[1:]
    dst[0] = byte(n.Priv)
    dst = dst[1:]
    return dst
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Bar1Mapping = uint8(src[0])
    src = src[1:]
    n.Priv = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_HOPPER_USERMODE_A_PARAMS) Packed() bool {
    return true
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_HOPPER_USERMODE_A_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) SizeBytes() int {
    return 108 +
        (*P64)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Owner))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Width))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Height))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Pitch))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Attr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Attr2))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Format))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ComprCovg))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ZcullCovg))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.RangeLo))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.RangeHi))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Alignment))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    dst = n.Address.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CtagOffset))
    dst = dst[4:]
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.InternalFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Tag))
    dst = dst[4:]
    return dst
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Owner = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Width = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Height = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Pitch = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Attr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Attr2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Format = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ComprCovg = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ZcullCovg = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    n.RangeLo = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.RangeHi = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Alignment = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.Address.UnmarshalUnsafe(src)
    n.CtagOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.InternalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Tag = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_ALLOCATION_PARAMS) Packed() bool {
    return n.Address.Packed() && n.HVASpace.Packed()
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.Address.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.Address.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Address.Packed() && n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Address.Packed() && n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Address.Packed() && n.HVASpace.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) SizeBytes() int {
    return 8 +
        (*NV_MEMORY_ALLOCATION_PARAMS)(nil).SizeBytes()
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) MarshalBytes(dst []byte) []byte {
    dst = n.NV_MEMORY_ALLOCATION_PARAMS.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumaNode))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) UnmarshalBytes(src []byte) []byte {
    src = n.NV_MEMORY_ALLOCATION_PARAMS.UnmarshalUnsafe(src)
    n.NumaNode = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) Packed() bool {
    return n.NV_MEMORY_ALLOCATION_PARAMS.Packed()
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) MarshalUnsafe(dst []byte) []byte {
    if n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) UnmarshalUnsafe(src []byte) []byte {
    if n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_ALLOCATION_PARAMS_V545) WriteTo(writer io.Writer) (int64, error) {
    if !n.NV_MEMORY_ALLOCATION_PARAMS.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_DESC_PARAMS) SizeBytes() int {
    return 24
}

func (n *NV_MEMORY_DESC_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.AddressSpace))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CacheAttrib))
    dst = dst[4:]
    return dst
}

func (n *NV_MEMORY_DESC_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.AddressSpace = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.CacheAttrib = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_DESC_PARAMS) Packed() bool {
    return true
}

func (n *NV_MEMORY_DESC_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_MEMORY_DESC_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_MEMORY_DESC_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_DESC_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_DESC_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_DESC_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_DESC_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) SizeBytes() int {
    return 1
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.unused)
    dst = dst[1:]
    return dst
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.unused = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) Packed() bool {
    return true
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    dst = n.HSemaphoreSurface.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.MaxQueueSize))
    dst = dst[4:]
    return dst
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    src = n.HSemaphoreSurface.UnmarshalUnsafe(src)
    n.MaxQueueSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) Packed() bool {
    return n.HSemaphoreSurface.Packed()
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if n.HSemaphoreSurface.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if n.HSemaphoreSurface.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HSemaphoreSurface.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HSemaphoreSurface.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !n.HSemaphoreSurface.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) SizeBytes() int {
    return 12 +
        (*NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) MarshalBytes(dst []byte) []byte {
    dst = n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.MarshalUnsafe(dst)
    dst = n.HNotificationMemory.MarshalUnsafe(dst)
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.NotificationOffset))
    dst = dst[8:]
    return dst
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) UnmarshalBytes(src []byte) []byte {
    src = n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.UnmarshalUnsafe(src)
    src = n.HNotificationMemory.UnmarshalUnsafe(src)
    src = src[4:]
    n.NotificationOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) Packed() bool {
    return n.HNotificationMemory.Packed() && n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.Packed()
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) MarshalUnsafe(dst []byte) []byte {
    if n.HNotificationMemory.Packed() && n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) UnmarshalUnsafe(src []byte) []byte {
    if n.HNotificationMemory.Packed() && n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HNotificationMemory.Packed() && n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HNotificationMemory.Packed() && n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V555) WriteTo(writer io.Writer) (int64, error) {
    if !n.HNotificationMemory.Packed() && n.NV_MEMORY_MAPPER_ALLOCATION_PARAMS_V550.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        1*4
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    dst = n.HVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.HVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) Packed() bool {
    return n.HVASpace.Packed()
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HVASpace.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProhibitMultipleInstances))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineInstance))
    dst = dst[4:]
    return dst
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ProhibitMultipleInstances = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_MSENC_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_MSENC_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 12
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProhibitMultipleInstances))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineInstance))
    dst = dst[4:]
    return dst
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ProhibitMultipleInstances = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.EngineInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_NVJPG_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_NVJPG_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 8
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ProhibitMultipleInstances))
    dst = dst[4:]
    return dst
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.ProhibitMultipleInstances = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_OFA_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_OFA_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) SizeBytes() int {
    return 4 +
        (*NV_OFA_ALLOCATION_PARAMETERS)(nil).SizeBytes()
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) MarshalBytes(dst []byte) []byte {
    dst = n.NV_OFA_ALLOCATION_PARAMETERS.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.EngineInstance))
    dst = dst[4:]
    return dst
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) UnmarshalBytes(src []byte) []byte {
    src = n.NV_OFA_ALLOCATION_PARAMETERS.UnmarshalUnsafe(src)
    n.EngineInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) Packed() bool {
    return n.NV_OFA_ALLOCATION_PARAMETERS.Packed()
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) MarshalUnsafe(dst []byte) []byte {
    if n.NV_OFA_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) UnmarshalUnsafe(src []byte) []byte {
    if n.NV_OFA_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_OFA_ALLOCATION_PARAMETERS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_OFA_ALLOCATION_PARAMETERS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_OFA_ALLOCATION_PARAMETERS_V545) WriteTo(writer io.Writer) (int64, error) {
    if !n.NV_OFA_ALLOCATION_PARAMETERS.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HSemaphoreMem.MarshalUnsafe(dst)
    dst = n.HMaxSubmittedMem.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.flags))
    dst = dst[8:]
    return dst
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HSemaphoreMem.UnmarshalUnsafe(src)
    src = n.HMaxSubmittedMem.UnmarshalUnsafe(src)
    n.flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) Packed() bool {
    return n.HMaxSubmittedMem.Packed() && n.HSemaphoreMem.Packed()
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HMaxSubmittedMem.Packed() && n.HSemaphoreMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HMaxSubmittedMem.Packed() && n.HSemaphoreMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMaxSubmittedMem.Packed() && n.HSemaphoreMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HMaxSubmittedMem.Packed() && n.HSemaphoreMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_SEMAPHORE_SURFACE_ALLOC_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HMaxSubmittedMem.Packed() && n.HSemaphoreMem.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) SizeBytes() int {
    return 44 +
        1*4
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VASize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VAStartInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VALimitInternal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.BigPageSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VABase))
    dst = dst[8:]
    return dst
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    n.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.VASize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VAStartInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.VALimitInternal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.BigPageSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.VABase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_VASPACE_ALLOCATION_PARAMETERS) Packed() bool {
    return true
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) SizeBytes() int {
    return 4 +
        (*NV_VASPACE_ALLOCATION_PARAMETERS)(nil).SizeBytes() +
        1*4
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) MarshalBytes(dst []byte) []byte {
    dst = n.NV_VASPACE_ALLOCATION_PARAMETERS.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Pasid))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) UnmarshalBytes(src []byte) []byte {
    src = n.NV_VASPACE_ALLOCATION_PARAMETERS.UnmarshalUnsafe(src)
    n.Pasid = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) Packed() bool {
    return n.NV_VASPACE_ALLOCATION_PARAMETERS.Packed()
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) MarshalUnsafe(dst []byte) []byte {
    if n.NV_VASPACE_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) UnmarshalUnsafe(src []byte) []byte {
    if n.NV_VASPACE_ALLOCATION_PARAMETERS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_VASPACE_ALLOCATION_PARAMETERS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.NV_VASPACE_ALLOCATION_PARAMETERS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV_VASPACE_ALLOCATION_PARAMETERS_V580) WriteTo(writer io.Writer) (int64, error) {
    if !n.NV_VASPACE_ALLOCATION_PARAMETERS.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *nv00f8Map) SizeBytes() int {
    return 12 +
        (*Handle)(nil).SizeBytes()
}

func (n *nv00f8Map) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.offset))
    dst = dst[8:]
    dst = n.hVidMem.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.flags))
    dst = dst[4:]
    return dst
}

func (n *nv00f8Map) UnmarshalBytes(src []byte) []byte {
    n.offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.hVidMem.UnmarshalUnsafe(src)
    n.flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *nv00f8Map) Packed() bool {
    return n.hVidMem.Packed()
}

func (n *nv00f8Map) MarshalUnsafe(dst []byte) []byte {
    if n.hVidMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *nv00f8Map) UnmarshalUnsafe(src []byte) []byte {
    if n.hVidMem.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *nv00f8Map) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.hVidMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *nv00f8Map) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *nv00f8Map) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.hVidMem.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *nv00f8Map) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *nv00f8Map) WriteTo(writer io.Writer) (int64, error) {
    if !n.hVidMem.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) SizeBytes() int {
    return 4 +
        4*NV0000_CTRL_GPU_MAX_PROBED_GPUS
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < NV0000_CTRL_GPU_MAX_PROBED_GPUS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GPUIDs[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.FailedID))
    dst = dst[4:]
    return dst
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < NV0000_CTRL_GPU_MAX_PROBED_GPUS; idx++ {
        n.GPUIDs[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    n.FailedID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) Packed() bool {
    return true
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_GPU_ATTACH_IDS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) SizeBytes() int {
    return 32 +
        (*P64)(nil).SizeBytes()
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.DeviceInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SubDeviceInstance))
    dst = dst[4:]
    dst = n.SzName.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SliStatus))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.BoardID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumaID))
    dst = dst[4:]
    return dst
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.GpuID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.GpuFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.DeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.SubDeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.SzName.UnmarshalUnsafe(src)
    n.SliStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.BoardID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.GpuInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.NumaID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) Packed() bool {
    return n.SzName.Packed()
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.SzName.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.SzName.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.SzName.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.SzName.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_GPU_GET_ID_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.SzName.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) SizeBytes() int {
    return 12 +
        1*NV0000_GPU_MAX_GID_LENGTH
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GPUID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < NV0000_GPU_MAX_GID_LENGTH; idx++ {
        dst[0] = byte(n.GPUUUID[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.UUIDStrLen))
    dst = dst[4:]
    return dst
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.GPUID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV0000_GPU_MAX_GID_LENGTH; idx++ {
        n.GPUUUID[idx] = src[0]
        src = src[1:]
    }
    n.UUIDStrLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) Packed() bool {
    return true
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_GPU_GET_UUID_FROM_GPU_ID_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) SizeBytes() int {
    return 4 +
        1*12
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Type))
    dst = dst[4:]
    for idx := 0; idx < 12; idx++ {
        dst[0] = byte(n.Data[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) UnmarshalBytes(src []byte) []byte {
    n.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 12; idx++ {
        n.Data[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) Packed() bool {
    return true
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) SizeBytes() int {
    return 10 +
        (*Handle)(nil).SizeBytes() +
        1*NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE +
        1*2 +
        (*Handle)(nil).SizeBytes()*NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_MAX_OBJECTS
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.MaxObjects))
    dst = dst[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        dst[0] = byte(p.Metadata[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_MAX_OBJECTS; idx++ {
        dst = p.Objects[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.NumObjects))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.Index))
    dst = dst[2:]
    return dst
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HDevice.UnmarshalUnsafe(src)
    p.MaxObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        p.Metadata[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 2; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_MAX_OBJECTS; idx++ {
        src = p.Objects[idx].UnmarshalUnsafe(src)
    }
    p.NumObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    p.Index = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) Packed() bool {
    return p.HDevice.Packed() && p.Objects[0].Packed()
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.HDevice.Packed() && p.Objects[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.HDevice.Packed() && p.Objects[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HDevice.Packed() && p.Objects[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HDevice.Packed() && p.Objects[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.HDevice.Packed() && p.Objects[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) SizeBytes() int {
    return 8 +
        (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT)(nil).SizeBytes()
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.Object.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Flags))
    dst = dst[4:]
    return dst
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.Object.UnmarshalUnsafe(src)
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) Packed() bool {
    return p.Object.Packed()
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.Object.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) SizeBytes() int {
    return 10 +
        1*NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE +
        1*2
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.DeviceInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.MaxObjects))
    dst = dst[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        dst[0] = byte(p.Metadata[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.DeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.MaxObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        p.Metadata[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 2; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) Packed() bool {
    return true
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) SizeBytes() int {
    return 14 +
        1*NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE +
        1*2
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.DeviceInstance))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.GpuInstanceID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.MaxObjects))
    dst = dst[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        dst[0] = byte(p.Metadata[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.DeviceInstance = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.GpuInstanceID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.MaxObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < NV0000_OS_UNIX_EXPORT_OBJECT_FD_BUFFER_SIZE; idx++ {
        p.Metadata[idx] = uint8(src[0])
        src = src[1:]
    }
    for idx := 0; idx < 2; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) Packed() bool {
    return true
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_GET_EXPORT_OBJECT_INFO_PARAMS_V545) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_TO_FD_MAX_OBJECTS +
        1*NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_TO_FD_MAX_OBJECTS
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.HParent.MarshalUnsafe(dst)
    for idx := 0; idx < NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_TO_FD_MAX_OBJECTS; idx++ {
        dst = p.Objects[idx].MarshalUnsafe(dst)
    }
    for idx := 0; idx < NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_TO_FD_MAX_OBJECTS; idx++ {
        dst[0] = byte(p.ObjectTypes[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.NumObjects))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.Index))
    dst = dst[2:]
    return dst
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HParent.UnmarshalUnsafe(src)
    for idx := 0; idx < NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_TO_FD_MAX_OBJECTS; idx++ {
        src = p.Objects[idx].UnmarshalUnsafe(src)
    }
    for idx := 0; idx < NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_TO_FD_MAX_OBJECTS; idx++ {
        p.ObjectTypes[idx] = uint8(src[0])
        src = src[1:]
    }
    p.NumObjects = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    p.Index = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) Packed() bool {
    return p.HParent.Packed() && p.Objects[0].Packed()
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.HParent.Packed() && p.Objects[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.HParent.Packed() && p.Objects[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HParent.Packed() && p.Objects[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HParent.Packed() && p.Objects[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECTS_FROM_FD_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.HParent.Packed() && p.Objects[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) SizeBytes() int {
    return 4 +
        (*NV0000_CTRL_OS_UNIX_EXPORT_OBJECT)(nil).SizeBytes()
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.Object.MarshalUnsafe(dst)
    return dst
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.Object.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) Packed() bool {
    return p.Object.Packed()
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.Object.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Object.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV0000_CTRL_OS_UNIX_IMPORT_OBJECT_FROM_FD_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.Object.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) SizeBytes() int {
    return 12 +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.SizeOfStrings))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.PDriverVersionBuffer.MarshalUnsafe(dst)
    dst = n.PVersionBuffer.MarshalUnsafe(dst)
    dst = n.PTitleBuffer.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ChangelistNumber))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.OfficialChangelistNumber))
    dst = dst[4:]
    return dst
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.SizeOfStrings = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.PDriverVersionBuffer.UnmarshalUnsafe(src)
    src = n.PVersionBuffer.UnmarshalUnsafe(src)
    src = n.PTitleBuffer.UnmarshalUnsafe(src)
    n.ChangelistNumber = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.OfficialChangelistNumber = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) Packed() bool {
    return n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed()
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_SYSTEM_GET_BUILD_VERSION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.PDriverVersionBuffer.Packed() && n.PTitleBuffer.Packed() && n.PVersionBuffer.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) SizeBytes() int {
    return 16 +
        4*NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS +
        1*NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE +
        1*7 +
        (*P64)(nil).SizeBytes()
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuIDs[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.GpuCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.P2PCaps))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.P2POptimalReadCEs))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.P2POptimalWriteCEs))
    dst = dst[4:]
    for idx := 0; idx < NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE; idx++ {
        dst[0] = byte(n.P2PCapsStatus[idx])
        dst = dst[1:]
    }
    dst = dst[1*(7):]
    dst = n.BusPeerIDs.MarshalUnsafe(dst)
    return dst
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS; idx++ {
        n.GpuIDs[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    n.GpuCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.P2PCaps = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.P2POptimalReadCEs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.P2POptimalWriteCEs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE; idx++ {
        n.P2PCapsStatus[idx] = uint8(src[0])
        src = src[1:]
    }
    src = src[1*(7):]
    src = n.BusPeerIDs.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) Packed() bool {
    return n.BusPeerIDs.Packed()
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.BusPeerIDs.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.BusPeerIDs.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusPeerIDs.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusPeerIDs.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.BusPeerIDs.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) SizeBytes() int {
    return 0 +
        (*NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    dst = n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.MarshalUnsafe(dst)
    dst = n.BusEgmPeerIDs.MarshalUnsafe(dst)
    return dst
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    src = n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.UnmarshalUnsafe(src)
    src = n.BusEgmPeerIDs.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) Packed() bool {
    return n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed()
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !n.BusEgmPeerIDs.Packed() && n.NV0000_CTRL_SYSTEM_GET_P2P_CAPS_PARAMS.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumChannels))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.PChannelHandleList.MarshalUnsafe(dst)
    dst = n.PChannelList.MarshalUnsafe(dst)
    return dst
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.NumChannels = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.PChannelHandleList.UnmarshalUnsafe(src)
    src = n.PChannelList.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) Packed() bool {
    return n.PChannelHandleList.Packed() && n.PChannelList.Packed()
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0080_CTRL_FIFO_GET_CHANNELLIST_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.PChannelHandleList.Packed() && n.PChannelList.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes()
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.CapsTblSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    dst = n.CapsTbl.MarshalUnsafe(dst)
    return dst
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.CapsTblSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    src = n.CapsTbl.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_CTRL_GET_CAPS_PARAMS) Packed() bool {
    return n.CapsTbl.Packed()
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.CapsTbl.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.CapsTbl.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.CapsTbl.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.CapsTbl.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0080_CTRL_GET_CAPS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.CapsTbl.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) SizeBytes() int {
    return 12 +
        1*4
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Route))
    dst = dst[8:]
    return dst
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    n.Route = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV0080_CTRL_GR_ROUTE_INFO) Packed() bool {
    return true
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV0080_CTRL_GR_ROUTE_INFO) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) SizeBytes() int {
    return 12 +
        (*Handle)(nil).SizeBytes()
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HSubDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DevDescriptor))
    dst = dst[8:]
    return dst
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HSubDevice.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.DevDescriptor = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) Packed() bool {
    return n.HSubDevice.Packed()
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HSubDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HSubDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV00FD_CTRL_ATTACH_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HSubDevice.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) SizeBytes() int {
    return 7 +
        1*3 +
        1*6 +
        (*P64)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES +
        (*Handle)(nil).SizeBytes()*NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.BDisable)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumChannels))
    dst = dst[4:]
    dst[0] = byte(n.BOnlyDisableScheduling)
    dst = dst[1:]
    dst[0] = byte(n.BRewindGpPut)
    dst = dst[1:]
    for idx := 0; idx < 6; idx++ {
        dst[0] = byte(n.Pad2[idx])
        dst = dst[1:]
    }
    dst = n.PRunlistPreemptEvent.MarshalUnsafe(dst)
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        dst = n.HClientList[idx].MarshalUnsafe(dst)
    }
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        dst = n.HChannelList[idx].MarshalUnsafe(dst)
    }
    return dst
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.BDisable = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    n.NumChannels = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.BOnlyDisableScheduling = uint8(src[0])
    src = src[1:]
    n.BRewindGpPut = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 6; idx++ {
        n.Pad2[idx] = src[0]
        src = src[1:]
    }
    src = n.PRunlistPreemptEvent.UnmarshalUnsafe(src)
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        src = n.HClientList[idx].UnmarshalUnsafe(src)
    }
    for idx := 0; idx < NV2080_CTRL_FIFO_DISABLE_CHANNELS_MAX_ENTRIES; idx++ {
        src = n.HChannelList[idx].UnmarshalUnsafe(src)
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) Packed() bool {
    return n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed()
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV2080_CTRL_FIFO_DISABLE_CHANNELS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HChannelList[0].Packed() && n.HClientList[0].Packed() && n.PRunlistPreemptEvent.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        4*2 +
        (*P64)(nil).SizeBytes() +
        (*NV0080_CTRL_GR_ROUTE_INFO)(nil).SizeBytes()
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HClientTarget.MarshalUnsafe(dst)
    dst = n.HChannelTarget.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.BNonTransactional))
    dst = dst[4:]
    for idx := 0; idx < 2; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Reserved00[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegOpCount))
    dst = dst[4:]
    dst = n.RegOps.MarshalUnsafe(dst)
    dst = n.GRRouteInfo.MarshalUnsafe(dst)
    return dst
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HClientTarget.UnmarshalUnsafe(src)
    src = n.HChannelTarget.UnmarshalUnsafe(src)
    n.BNonTransactional = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 2; idx++ {
        n.Reserved00[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    n.RegOpCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.RegOps.UnmarshalUnsafe(src)
    src = n.GRRouteInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) Packed() bool {
    return n.GRRouteInfo.Packed() && n.HChannelTarget.Packed() && n.HClientTarget.Packed() && n.RegOps.Packed()
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.GRRouteInfo.Packed() && n.HChannelTarget.Packed() && n.HClientTarget.Packed() && n.RegOps.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.GRRouteInfo.Packed() && n.HChannelTarget.Packed() && n.HClientTarget.Packed() && n.RegOps.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.GRRouteInfo.Packed() && n.HChannelTarget.Packed() && n.HClientTarget.Packed() && n.RegOps.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.GRRouteInfo.Packed() && n.HChannelTarget.Packed() && n.HClientTarget.Packed() && n.RegOps.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV2080_CTRL_GPU_EXEC_REG_OPS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.GRRouteInfo.Packed() && n.HChannelTarget.Packed() && n.HClientTarget.Packed() && n.RegOps.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV2080_CTRL_GPU_REG_OP) SizeBytes() int {
    return 32
}

func (n *NV2080_CTRL_GPU_REG_OP) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.RegOp)
    dst = dst[1:]
    dst[0] = byte(n.RegType)
    dst = dst[1:]
    dst[0] = byte(n.RegStatus)
    dst = dst[1:]
    dst[0] = byte(n.RegQuad)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegGroupMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegSubGroupMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegOffset))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegValueHi))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegValueLo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegAndNMaskHi))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RegAndNMaskLo))
    dst = dst[4:]
    return dst
}

func (n *NV2080_CTRL_GPU_REG_OP) UnmarshalBytes(src []byte) []byte {
    n.RegOp = uint8(src[0])
    src = src[1:]
    n.RegType = uint8(src[0])
    src = src[1:]
    n.RegStatus = uint8(src[0])
    src = src[1:]
    n.RegQuad = uint8(src[0])
    src = src[1:]
    n.RegGroupMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.RegSubGroupMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.RegOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.RegValueHi = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.RegValueLo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.RegAndNMaskHi = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.RegAndNMaskLo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV2080_CTRL_GPU_REG_OP) Packed() bool {
    return true
}

func (n *NV2080_CTRL_GPU_REG_OP) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV2080_CTRL_GPU_REG_OP) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV2080_CTRL_GPU_REG_OP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_CTRL_GPU_REG_OP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV2080_CTRL_GPU_REG_OP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV2080_CTRL_GPU_REG_OP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV2080_CTRL_GPU_REG_OP) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) SizeBytes() int {
    return 0 +
        (*NvxxxCtrlXxxGetInfoParams)(nil).SizeBytes() +
        (*NV0080_CTRL_GR_ROUTE_INFO)(nil).SizeBytes()
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.NvxxxCtrlXxxGetInfoParams.MarshalUnsafe(dst)
    dst = p.GRRouteInfo.MarshalUnsafe(dst)
    return dst
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.NvxxxCtrlXxxGetInfoParams.UnmarshalUnsafe(src)
    src = p.GRRouteInfo.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) Packed() bool {
    return p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed()
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NV2080_CTRL_GR_GET_INFO_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GRRouteInfo.Packed() && p.NvxxxCtrlXxxGetInfoParams.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) SizeBytes() int {
    return 8
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Result))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Checksum))
    dst = dst[4:]
    return dst
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) UnmarshalBytes(src []byte) []byte {
    n.Result = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Checksum = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) Packed() bool {
    return true
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV208F_CTRL_GPU_VERIFY_INFOROM_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        1*4
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = n.HVASpace.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.VASpaceToken))
    dst = dst[8:]
    return dst
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = n.HVASpace.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    n.VASpaceToken = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) Packed() bool {
    return n.HVASpace.Packed()
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NV503C_CTRL_REGISTER_VA_SPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HVASpace.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVXXXX_CTRL_XXX_INFO) SizeBytes() int {
    return 8
}

func (n *NVXXXX_CTRL_XXX_INFO) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Data))
    dst = dst[4:]
    return dst
}

func (n *NVXXXX_CTRL_XXX_INFO) UnmarshalBytes(src []byte) []byte {
    n.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Data = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVXXXX_CTRL_XXX_INFO) Packed() bool {
    return true
}

func (n *NVXXXX_CTRL_XXX_INFO) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NVXXXX_CTRL_XXX_INFO) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NVXXXX_CTRL_XXX_INFO) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVXXXX_CTRL_XXX_INFO) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVXXXX_CTRL_XXX_INFO) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVXXXX_CTRL_XXX_INFO) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVXXXX_CTRL_XXX_INFO) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (p *NvxxxCtrlXxxGetInfoParams) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes()
}

func (p *NvxxxCtrlXxxGetInfoParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.InfoListSize))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    dst = p.InfoList.MarshalUnsafe(dst)
    return dst
}

func (p *NvxxxCtrlXxxGetInfoParams) UnmarshalBytes(src []byte) []byte {
    p.InfoListSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    src = p.InfoList.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NvxxxCtrlXxxGetInfoParams) Packed() bool {
    return p.InfoList.Packed()
}

func (p *NvxxxCtrlXxxGetInfoParams) MarshalUnsafe(dst []byte) []byte {
    if p.InfoList.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NvxxxCtrlXxxGetInfoParams) UnmarshalUnsafe(src []byte) []byte {
    if p.InfoList.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NvxxxCtrlXxxGetInfoParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.InfoList.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NvxxxCtrlXxxGetInfoParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NvxxxCtrlXxxGetInfoParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.InfoList.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NvxxxCtrlXxxGetInfoParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NvxxxCtrlXxxGetInfoParams) WriteTo(writer io.Writer) (int64, error) {
    if !p.InfoList.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (r *RmapiParamNvU32List) SizeBytes() int {
    return 4 +
        1*4 +
        (*P64)(nil).SizeBytes()
}

func (r *RmapiParamNvU32List) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.NumElems))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(r.Pad[idx])
        dst = dst[1:]
    }
    dst = r.List.MarshalUnsafe(dst)
    return dst
}

func (r *RmapiParamNvU32List) UnmarshalBytes(src []byte) []byte {
    r.NumElems = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        r.Pad[idx] = src[0]
        src = src[1:]
    }
    src = r.List.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RmapiParamNvU32List) Packed() bool {
    return r.List.Packed()
}

func (r *RmapiParamNvU32List) MarshalUnsafe(dst []byte) []byte {
    if r.List.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    return r.MarshalBytes(dst)
}

func (r *RmapiParamNvU32List) UnmarshalUnsafe(src []byte) []byte {
    if r.List.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return r.UnmarshalBytes(src)
}

func (r *RmapiParamNvU32List) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.List.Packed() {
        buf := cc.CopyScratchBuffer(r.SizeBytes())
        r.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RmapiParamNvU32List) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RmapiParamNvU32List) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.List.Packed() {
        buf := cc.CopyScratchBuffer(r.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        r.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RmapiParamNvU32List) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RmapiParamNvU32List) WriteTo(writer io.Writer) (int64, error) {
    if !r.List.Packed() {
        buf := make([]byte, r.SizeBytes())
        r.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (p *IoctlAllocOSEvent) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *IoctlAllocOSEvent) MarshalBytes(dst []byte) []byte {
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    return dst
}

func (p *IoctlAllocOSEvent) UnmarshalBytes(src []byte) []byte {
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HDevice.UnmarshalUnsafe(src)
    p.FD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlAllocOSEvent) Packed() bool {
    return p.HClient.Packed() && p.HDevice.Packed()
}

func (p *IoctlAllocOSEvent) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlAllocOSEvent) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlAllocOSEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlAllocOSEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlAllocOSEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlAllocOSEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlAllocOSEvent) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (i *IoctlCardInfo) SizeBytes() int {
    return 43 +
        1*3 +
        (*PCIInfo)(nil).SizeBytes() +
        1*2 +
        1*10 +
        1*2
}

func (i *IoctlCardInfo) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Valid)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(i.Pad0[idx])
        dst = dst[1:]
    }
    dst = i.PCIInfo.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.GPUID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.InterruptLine))
    dst = dst[2:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(i.Pad1[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.RegAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.RegSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.FBAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.FBSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.MinorNumber))
    dst = dst[4:]
    for idx := 0; idx < 10; idx++ {
        dst[0] = byte(i.DevName[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(i.Pad2[idx])
        dst = dst[1:]
    }
    return dst
}

func (i *IoctlCardInfo) UnmarshalBytes(src []byte) []byte {
    i.Valid = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        i.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = i.PCIInfo.UnmarshalUnsafe(src)
    i.GPUID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.InterruptLine = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 2; idx++ {
        i.Pad1[idx] = src[0]
        src = src[1:]
    }
    i.RegAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.RegSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.FBAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.FBSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.MinorNumber = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 10; idx++ {
        i.DevName[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 2; idx++ {
        i.Pad2[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlCardInfo) Packed() bool {
    return i.PCIInfo.Packed()
}

func (i *IoctlCardInfo) MarshalUnsafe(dst []byte) []byte {
    if i.PCIInfo.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IoctlCardInfo) UnmarshalUnsafe(src []byte) []byte {
    if i.PCIInfo.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IoctlCardInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.PCIInfo.Packed() {
        buf := cc.CopyScratchBuffer(i.SizeBytes())
        i.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IoctlCardInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IoctlCardInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.PCIInfo.Packed() {
        buf := cc.CopyScratchBuffer(i.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        i.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IoctlCardInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IoctlCardInfo) WriteTo(writer io.Writer) (int64, error) {
    if !i.PCIInfo.Packed() {
        buf := make([]byte, i.SizeBytes())
        i.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (p *IoctlExportToDMABufFD) SizeBytes() int {
    return 36 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()*NV_DMABUF_EXPORT_MAX_HANDLES +
        8*NV_DMABUF_EXPORT_MAX_HANDLES +
        8*NV_DMABUF_EXPORT_MAX_HANDLES
}

func (p *IoctlExportToDMABufFD) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.TotalObjects))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumObjects))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad0))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.TotalSize))
    dst = dst[8:]
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        dst = p.Handles[idx].MarshalUnsafe(dst)
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offsets[idx]))
        dst = dst[8:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Sizes[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad1))
    dst = dst[4:]
    return dst
}

func (p *IoctlExportToDMABufFD) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    p.TotalObjects = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.NumObjects = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Pad0 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.TotalSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        src = p.Handles[idx].UnmarshalUnsafe(src)
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        p.Offsets[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        p.Sizes[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Pad1 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlExportToDMABufFD) Packed() bool {
    return p.HClient.Packed() && p.Handles[0].Packed()
}

func (p *IoctlExportToDMABufFD) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.Handles[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlExportToDMABufFD) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.Handles[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlExportToDMABufFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlExportToDMABufFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlExportToDMABufFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlExportToDMABufFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlExportToDMABufFD) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *IoctlExportToDMABufFD_V570) SizeBytes() int {
    return 41 +
        (*Handle)(nil).SizeBytes() +
        1*3 +
        (*Handle)(nil).SizeBytes()*NV_DMABUF_EXPORT_MAX_HANDLES +
        8*NV_DMABUF_EXPORT_MAX_HANDLES +
        8*NV_DMABUF_EXPORT_MAX_HANDLES
}

func (p *IoctlExportToDMABufFD_V570) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.TotalObjects))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumObjects))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad0))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.TotalSize))
    dst = dst[8:]
    dst[0] = byte(p.MappingType)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad1[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        dst = p.Handles[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad2))
    dst = dst[4:]
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offsets[idx]))
        dst = dst[8:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Sizes[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad3))
    dst = dst[4:]
    return dst
}

func (p *IoctlExportToDMABufFD_V570) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    p.TotalObjects = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.NumObjects = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Pad0 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.TotalSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.MappingType = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad1[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        src = p.Handles[idx].UnmarshalUnsafe(src)
    }
    p.Pad2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        p.Offsets[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        p.Sizes[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Pad3 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlExportToDMABufFD_V570) Packed() bool {
    return p.HClient.Packed() && p.Handles[0].Packed()
}

func (p *IoctlExportToDMABufFD_V570) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.Handles[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlExportToDMABufFD_V570) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.Handles[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlExportToDMABufFD_V570) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlExportToDMABufFD_V570) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlExportToDMABufFD_V570) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlExportToDMABufFD_V570) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlExportToDMABufFD_V570) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *IoctlExportToDMABufFD_V580) SizeBytes() int {
    return 42 +
        (*Handle)(nil).SizeBytes() +
        1*2 +
        (*Handle)(nil).SizeBytes()*NV_DMABUF_EXPORT_MAX_HANDLES +
        8*NV_DMABUF_EXPORT_MAX_HANDLES +
        8*NV_DMABUF_EXPORT_MAX_HANDLES
}

func (p *IoctlExportToDMABufFD_V580) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.TotalObjects))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumObjects))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad0))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.TotalSize))
    dst = dst[8:]
    dst[0] = byte(p.MappingType)
    dst = dst[1:]
    dst[0] = byte(p.AllowMmap)
    dst = dst[1:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(p.Pad1[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        dst = p.Handles[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad2))
    dst = dst[4:]
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offsets[idx]))
        dst = dst[8:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Sizes[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Pad3))
    dst = dst[4:]
    return dst
}

func (p *IoctlExportToDMABufFD_V580) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    p.TotalObjects = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.NumObjects = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Pad0 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.TotalSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.MappingType = uint8(src[0])
    src = src[1:]
    p.AllowMmap = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 2; idx++ {
        p.Pad1[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        src = p.Handles[idx].UnmarshalUnsafe(src)
    }
    p.Pad2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        p.Offsets[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    for idx := 0; idx < NV_DMABUF_EXPORT_MAX_HANDLES; idx++ {
        p.Sizes[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Pad3 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlExportToDMABufFD_V580) Packed() bool {
    return p.HClient.Packed() && p.Handles[0].Packed()
}

func (p *IoctlExportToDMABufFD_V580) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.Handles[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlExportToDMABufFD_V580) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.Handles[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlExportToDMABufFD_V580) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlExportToDMABufFD_V580) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlExportToDMABufFD_V580) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlExportToDMABufFD_V580) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlExportToDMABufFD_V580) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.Handles[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *IoctlFreeOSEvent) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *IoctlFreeOSEvent) MarshalBytes(dst []byte) []byte {
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HDevice.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    return dst
}

func (p *IoctlFreeOSEvent) UnmarshalBytes(src []byte) []byte {
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HDevice.UnmarshalUnsafe(src)
    p.FD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlFreeOSEvent) Packed() bool {
    return p.HClient.Packed() && p.HDevice.Packed()
}

func (p *IoctlFreeOSEvent) MarshalUnsafe(dst []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlFreeOSEvent) UnmarshalUnsafe(src []byte) []byte {
    if p.HClient.Packed() && p.HDevice.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlFreeOSEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlFreeOSEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlFreeOSEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlFreeOSEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlFreeOSEvent) WriteTo(writer io.Writer) (int64, error) {
    if !p.HClient.Packed() && p.HDevice.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *IoctlNVOS02ParametersWithFD) SizeBytes() int {
    return 4 +
        (*NVOS02_PARAMETERS)(nil).SizeBytes() +
        1*4
}

func (p *IoctlNVOS02ParametersWithFD) MarshalBytes(dst []byte) []byte {
    dst = p.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *IoctlNVOS02ParametersWithFD) UnmarshalBytes(src []byte) []byte {
    src = p.Params.UnmarshalUnsafe(src)
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlNVOS02ParametersWithFD) Packed() bool {
    return p.Params.Packed()
}

func (p *IoctlNVOS02ParametersWithFD) MarshalUnsafe(dst []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlNVOS02ParametersWithFD) UnmarshalUnsafe(src []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlNVOS02ParametersWithFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlNVOS02ParametersWithFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlNVOS02ParametersWithFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlNVOS02ParametersWithFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlNVOS02ParametersWithFD) WriteTo(writer io.Writer) (int64, error) {
    if !p.Params.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *IoctlNVOS33ParametersWithFD) SizeBytes() int {
    return 4 +
        (*NVOS33_PARAMETERS)(nil).SizeBytes() +
        1*4
}

func (p *IoctlNVOS33ParametersWithFD) MarshalBytes(dst []byte) []byte {
    dst = p.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *IoctlNVOS33ParametersWithFD) UnmarshalBytes(src []byte) []byte {
    src = p.Params.UnmarshalUnsafe(src)
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlNVOS33ParametersWithFD) Packed() bool {
    return p.Params.Packed()
}

func (p *IoctlNVOS33ParametersWithFD) MarshalUnsafe(dst []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *IoctlNVOS33ParametersWithFD) UnmarshalUnsafe(src []byte) []byte {
    if p.Params.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *IoctlNVOS33ParametersWithFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlNVOS33ParametersWithFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlNVOS33ParametersWithFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.Params.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlNVOS33ParametersWithFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlNVOS33ParametersWithFD) WriteTo(writer io.Writer) (int64, error) {
    if !p.Params.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (i *IoctlRegisterFD) SizeBytes() int {
    return 4
}

func (i *IoctlRegisterFD) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CtlFD))
    dst = dst[4:]
    return dst
}

func (i *IoctlRegisterFD) UnmarshalBytes(src []byte) []byte {
    i.CtlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlRegisterFD) Packed() bool {
    return true
}

func (i *IoctlRegisterFD) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IoctlRegisterFD) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IoctlRegisterFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IoctlRegisterFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IoctlRegisterFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IoctlRegisterFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IoctlRegisterFD) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IoctlSysParams) SizeBytes() int {
    return 8
}

func (i *IoctlSysParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.MemblockSize))
    dst = dst[8:]
    return dst
}

func (i *IoctlSysParams) UnmarshalBytes(src []byte) []byte {
    i.MemblockSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IoctlSysParams) Packed() bool {
    return true
}

func (i *IoctlSysParams) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IoctlSysParams) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IoctlSysParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IoctlSysParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IoctlSysParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IoctlSysParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IoctlSysParams) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (p *IoctlWaitOpenComplete) SizeBytes() int {
    return 8
}

func (p *IoctlWaitOpenComplete) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Rc))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.AdapterStatus))
    dst = dst[4:]
    return dst
}

func (p *IoctlWaitOpenComplete) UnmarshalBytes(src []byte) []byte {
    p.Rc = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.AdapterStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *IoctlWaitOpenComplete) Packed() bool {
    return true
}

func (p *IoctlWaitOpenComplete) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *IoctlWaitOpenComplete) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *IoctlWaitOpenComplete) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlWaitOpenComplete) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *IoctlWaitOpenComplete) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *IoctlWaitOpenComplete) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *IoctlWaitOpenComplete) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *NVOS00_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *NVOS00_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = p.HRoot.MarshalUnsafe(dst)
    dst = p.HObjectParent.MarshalUnsafe(dst)
    dst = p.HObjectOld.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Status))
    dst = dst[4:]
    return dst
}

func (p *NVOS00_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = p.HRoot.UnmarshalUnsafe(src)
    src = p.HObjectParent.UnmarshalUnsafe(src)
    src = p.HObjectOld.UnmarshalUnsafe(src)
    p.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *NVOS00_PARAMETERS) Packed() bool {
    return p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed()
}

func (p *NVOS00_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *NVOS00_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *NVOS00_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NVOS00_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *NVOS00_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *NVOS00_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *NVOS00_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !p.HObjectOld.Packed() && p.HObjectParent.Packed() && p.HRoot.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (n *NVOS02_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes() +
        1*4
}

func (n *NVOS02_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.PMemory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS02_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.PMemory.UnmarshalUnsafe(src)
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS02_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed()
}

func (n *NVOS02_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS02_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS02_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS02_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS02_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS02_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS02_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PMemory.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS21_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NVOS21_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    dst = n.PAllocParms.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

func (n *NVOS21_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    src = n.PAllocParms.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS21_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed()
}

func (n *NVOS21_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS21_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS21_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS21_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS21_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS21_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS21_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS30_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        1*4
}

func (n *NVOS30_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Channel.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.NumChannels))
    dst = dst[4:]
    dst = n.Clients.MarshalUnsafe(dst)
    dst = n.Devices.MarshalUnsafe(dst)
    dst = n.Channels.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Timeout))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS30_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Channel.UnmarshalUnsafe(src)
    n.NumChannels = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Clients.UnmarshalUnsafe(src)
    src = n.Devices.UnmarshalUnsafe(src)
    src = n.Channels.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Timeout = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS30_PARAMETERS) Packed() bool {
    return n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed()
}

func (n *NVOS30_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS30_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS30_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS30_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS30_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS30_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS30_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Channel.Packed() && n.Channels.Packed() && n.Client.Packed() && n.Clients.Packed() && n.Device.Packed() && n.Devices.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS32_PARAMETERS) SizeBytes() int {
    return 26 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*2 +
        1*144
}

func (n *NVOS32_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Function))
    dst = dst[4:]
    dst = n.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.IVCHeapNumber))
    dst = dst[2:]
    for idx := 0; idx < 2; idx++ {
        dst[0] = byte(n.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Total))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Free))
    dst = dst[8:]
    for idx := 0; idx < 144; idx++ {
        dst[0] = byte(n.Data[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS32_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    n.Function = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HVASpace.UnmarshalUnsafe(src)
    n.IVCHeapNumber = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < 2; idx++ {
        n.Pad[idx] = src[0]
        src = src[1:]
    }
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Total = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Free = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 144; idx++ {
        n.Data[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS32_PARAMETERS) Packed() bool {
    return n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed()
}

func (n *NVOS32_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS32_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS32_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS32_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS32_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS32_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS32_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HObjectParent.Packed() && n.HRoot.Packed() && n.HVASpace.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS33_PARAMETERS) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes()
}

func (n *NVOS33_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HDevice.MarshalUnsafe(dst)
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Length))
    dst = dst[8:]
    dst = n.PLinearAddress.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    return dst
}

func (n *NVOS33_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HDevice.UnmarshalUnsafe(src)
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = n.PLinearAddress.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS33_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed()
}

func (n *NVOS33_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS33_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS33_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS33_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS33_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS33_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS33_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS34_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes()
}

func (n *NVOS34_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HDevice.MarshalUnsafe(dst)
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.PLinearAddress.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    return dst
}

func (n *NVOS34_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HDevice.UnmarshalUnsafe(src)
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.PLinearAddress.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS34_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed()
}

func (n *NVOS34_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS34_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS34_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS34_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS34_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS34_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS34_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PLinearAddress.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS39_PARAMETERS) SizeBytes() int {
    return 28 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (n *NVOS39_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HSubDevice.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Selector))
    dst = dst[4:]
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Limit))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS39_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HSubDevice.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Selector = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Limit = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS39_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed()
}

func (n *NVOS39_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS39_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS39_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS39_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS39_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS39_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS39_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HMemory.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HSubDevice.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS46_PARAMETERS) SizeBytes() int {
    return 32 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (n *NVOS46_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS46_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS46_PARAMETERS) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

func (n *NVOS46_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS46_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS46_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS46_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS46_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS46_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS46_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS46_PARAMETERS_V580) SizeBytes() int {
    return 40 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (n *NVOS46_PARAMETERS_V580) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags2))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.KindOverride))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS46_PARAMETERS_V580) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags2 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.KindOverride = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS46_PARAMETERS_V580) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

func (n *NVOS46_PARAMETERS_V580) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS46_PARAMETERS_V580) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS46_PARAMETERS_V580) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS46_PARAMETERS_V580) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS46_PARAMETERS_V580) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS46_PARAMETERS_V580) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS46_PARAMETERS_V580) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS47_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (n *NVOS47_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS47_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS47_PARAMETERS) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

func (n *NVOS47_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS47_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS47_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS47_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS47_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS47_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS47_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS47_PARAMETERS_V550) SizeBytes() int {
    return 24 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (n *NVOS47_PARAMETERS_V550) MarshalBytes(dst []byte) []byte {
    dst = n.Client.MarshalUnsafe(dst)
    dst = n.Device.MarshalUnsafe(dst)
    dst = n.Dma.MarshalUnsafe(dst)
    dst = n.Memory.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.DmaOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(n.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS47_PARAMETERS_V550) UnmarshalBytes(src []byte) []byte {
    src = n.Client.UnmarshalUnsafe(src)
    src = n.Device.UnmarshalUnsafe(src)
    src = n.Dma.UnmarshalUnsafe(src)
    src = n.Memory.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    n.DmaOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS47_PARAMETERS_V550) Packed() bool {
    return n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed()
}

func (n *NVOS47_PARAMETERS_V550) MarshalUnsafe(dst []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS47_PARAMETERS_V550) UnmarshalUnsafe(src []byte) []byte {
    if n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS47_PARAMETERS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS47_PARAMETERS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS47_PARAMETERS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS47_PARAMETERS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS47_PARAMETERS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !n.Client.Packed() && n.Device.Packed() && n.Dma.Packed() && n.Memory.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS54_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NVOS54_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.Params.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

func (n *NVOS54_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    n.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Params.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS54_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed()
}

func (n *NVOS54_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS54_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS54_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS54_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS54_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS54_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS54_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.Params.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS55_PARAMETERS) SizeBytes() int {
    return 8 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (n *NVOS55_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HParent.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    dst = n.HClientSrc.MarshalUnsafe(dst)
    dst = n.HObjectSrc.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

func (n *NVOS55_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HParent.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    src = n.HClientSrc.UnmarshalUnsafe(src)
    src = n.HObjectSrc.UnmarshalUnsafe(src)
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS55_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed()
}

func (n *NVOS55_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS55_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS55_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS55_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS55_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS55_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS55_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HClientSrc.Packed() && n.HObject.Packed() && n.HObjectSrc.Packed() && n.HParent.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS56_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        1*4
}

func (n *NVOS56_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HDevice.MarshalUnsafe(dst)
    dst = n.HMemory.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad0[idx])
        dst = dst[1:]
    }
    dst = n.POldCPUAddress.MarshalUnsafe(dst)
    dst = n.PNewCPUAddress.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.Pad1[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NVOS56_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HDevice.UnmarshalUnsafe(src)
    src = n.HMemory.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        n.Pad0[idx] = src[0]
        src = src[1:]
    }
    src = n.POldCPUAddress.UnmarshalUnsafe(src)
    src = n.PNewCPUAddress.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.Pad1[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS56_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed()
}

func (n *NVOS56_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS56_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS56_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS56_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS56_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS56_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS56_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HDevice.Packed() && n.HMemory.Packed() && n.PNewCPUAddress.Packed() && n.POldCPUAddress.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS57_PARAMETERS) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*RS_SHARE_POLICY)(nil).SizeBytes()
}

func (n *NVOS57_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HClient.MarshalUnsafe(dst)
    dst = n.HObject.MarshalUnsafe(dst)
    dst = n.SharePolicy.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    return dst
}

func (n *NVOS57_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HClient.UnmarshalUnsafe(src)
    src = n.HObject.UnmarshalUnsafe(src)
    src = n.SharePolicy.UnmarshalUnsafe(src)
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS57_PARAMETERS) Packed() bool {
    return n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed()
}

func (n *NVOS57_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS57_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS57_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS57_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS57_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS57_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS57_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClient.Packed() && n.HObject.Packed() && n.SharePolicy.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NVOS64_PARAMETERS) SizeBytes() int {
    return 16 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*ClassID)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes() +
        (*P64)(nil).SizeBytes()
}

func (n *NVOS64_PARAMETERS) MarshalBytes(dst []byte) []byte {
    dst = n.HRoot.MarshalUnsafe(dst)
    dst = n.HObjectParent.MarshalUnsafe(dst)
    dst = n.HObjectNew.MarshalUnsafe(dst)
    dst = n.HClass.MarshalUnsafe(dst)
    dst = n.PAllocParms.MarshalUnsafe(dst)
    dst = n.PRightsRequested.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.ParamsSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Status))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (n *NVOS64_PARAMETERS) UnmarshalBytes(src []byte) []byte {
    src = n.HRoot.UnmarshalUnsafe(src)
    src = n.HObjectParent.UnmarshalUnsafe(src)
    src = n.HObjectNew.UnmarshalUnsafe(src)
    src = n.HClass.UnmarshalUnsafe(src)
    src = n.PAllocParms.UnmarshalUnsafe(src)
    src = n.PRightsRequested.UnmarshalUnsafe(src)
    n.ParamsSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Status = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NVOS64_PARAMETERS) Packed() bool {
    return n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed()
}

func (n *NVOS64_PARAMETERS) MarshalUnsafe(dst []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NVOS64_PARAMETERS) UnmarshalUnsafe(src []byte) []byte {
    if n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NVOS64_PARAMETERS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        n.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS64_PARAMETERS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NVOS64_PARAMETERS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        buf := cc.CopyScratchBuffer(n.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        n.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NVOS64_PARAMETERS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NVOS64_PARAMETERS) WriteTo(writer io.Writer) (int64, error) {
    if !n.HClass.Packed() && n.HObjectNew.Packed() && n.HObjectParent.Packed() && n.HRoot.Packed() && n.PAllocParms.Packed() && n.PRightsRequested.Packed() {
        buf := make([]byte, n.SizeBytes())
        n.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (p *PCIInfo) SizeBytes() int {
    return 12
}

func (p *PCIInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Domain))
    dst = dst[4:]
    dst[0] = byte(p.Bus)
    dst = dst[1:]
    dst[0] = byte(p.Slot)
    dst = dst[1:]
    dst[0] = byte(p.Function)
    dst = dst[1:]
    dst[0] = byte(p.Pad0)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.VendorID))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.DeviceID))
    dst = dst[2:]
    return dst
}

func (p *PCIInfo) UnmarshalBytes(src []byte) []byte {
    p.Domain = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Bus = uint8(src[0])
    src = src[1:]
    p.Slot = uint8(src[0])
    src = src[1:]
    p.Function = uint8(src[0])
    src = src[1:]
    p.Pad0 = uint8(src[0])
    src = src[1:]
    p.VendorID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    p.DeviceID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PCIInfo) Packed() bool {
    return true
}

func (p *PCIInfo) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *PCIInfo) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *PCIInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *PCIInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *PCIInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *PCIInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *PCIInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (r *RMAPIVersion) SizeBytes() int {
    return 8 +
        1*64
}

func (r *RMAPIVersion) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Reply))
    dst = dst[4:]
    for idx := 0; idx < 64; idx++ {
        dst[0] = byte(r.VersionString[idx])
        dst = dst[1:]
    }
    return dst
}

func (r *RMAPIVersion) UnmarshalBytes(src []byte) []byte {
    r.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Reply = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 64; idx++ {
        r.VersionString[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RMAPIVersion) Packed() bool {
    return true
}

func (r *RMAPIVersion) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

func (r *RMAPIVersion) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (r *RMAPIVersion) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RMAPIVersion) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RMAPIVersion) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RMAPIVersion) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RMAPIVersion) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (h *Handle) SizeBytes() int {
    return 4
}

func (h *Handle) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(h.Val))
    dst = dst[4:]
    return dst
}

func (h *Handle) UnmarshalBytes(src []byte) []byte {
    h.Val = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (h *Handle) Packed() bool {
    return true
}

func (h *Handle) MarshalUnsafe(dst []byte) []byte {
    size := h.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(h), uintptr(size))
    return dst[size:]
}

func (h *Handle) UnmarshalUnsafe(src []byte) []byte {
    size := h.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(h), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (h *Handle) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(h)))
    hdr.Len = h.SizeBytes()
    hdr.Cap = h.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(h)
    return length, err
}

func (h *Handle) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return h.CopyOutN(cc, addr, h.SizeBytes())
}

func (h *Handle) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(h)))
    hdr.Len = h.SizeBytes()
    hdr.Cap = h.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(h)
    return length, err
}

func (h *Handle) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return h.CopyInN(cc, addr, h.SizeBytes())
}

func (h *Handle) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(h)))
    hdr.Len = h.SizeBytes()
    hdr.Cap = h.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(h)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (n *NvUUID) SizeBytes() int {
    return 1 * 16
}

func (n *NvUUID) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(n[idx])
        dst = dst[1:]
    }
    return dst
}

func (n *NvUUID) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        n[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NvUUID) Packed() bool {
    return true
}

func (n *NvUUID) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&n[0]), uintptr(size))
    return dst[size:]
}

func (n *NvUUID) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NvUUID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NvUUID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NvUUID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NvUUID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NvUUID) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (p *P64) SizeBytes() int {
    return 8
}

func (p *P64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*p))
    return dst[8:]
}

func (p *P64) UnmarshalBytes(src []byte) []byte {
    *p = P64(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *P64) Packed() bool {
    return true
}

func (p *P64) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *P64) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *P64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *P64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *P64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *P64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *P64) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (r *RS_ACCESS_MASK) SizeBytes() int {
    return 0 +
        4*SDK_RS_ACCESS_MAX_LIMBS
}

func (r *RS_ACCESS_MASK) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < SDK_RS_ACCESS_MAX_LIMBS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Limbs[idx]))
        dst = dst[4:]
    }
    return dst
}

func (r *RS_ACCESS_MASK) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < SDK_RS_ACCESS_MAX_LIMBS; idx++ {
        r.Limbs[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RS_ACCESS_MASK) Packed() bool {
    return true
}

func (r *RS_ACCESS_MASK) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

func (r *RS_ACCESS_MASK) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (r *RS_ACCESS_MASK) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RS_ACCESS_MASK) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RS_ACCESS_MASK) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RS_ACCESS_MASK) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RS_ACCESS_MASK) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (r *RS_SHARE_POLICY) SizeBytes() int {
    return 7 +
        (*RS_ACCESS_MASK)(nil).SizeBytes() +
        1*1
}

func (r *RS_SHARE_POLICY) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Target))
    dst = dst[4:]
    dst = r.AccessMask.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(r.Type))
    dst = dst[2:]
    dst[0] = byte(r.Action)
    dst = dst[1:]
    for idx := 0; idx < 1; idx++ {
        dst[0] = byte(r.Pad[idx])
        dst = dst[1:]
    }
    return dst
}

func (r *RS_SHARE_POLICY) UnmarshalBytes(src []byte) []byte {
    r.Target = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = r.AccessMask.UnmarshalUnsafe(src)
    r.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    r.Action = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 1; idx++ {
        r.Pad[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RS_SHARE_POLICY) Packed() bool {
    return r.AccessMask.Packed()
}

func (r *RS_SHARE_POLICY) MarshalUnsafe(dst []byte) []byte {
    if r.AccessMask.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    return r.MarshalBytes(dst)
}

func (r *RS_SHARE_POLICY) UnmarshalUnsafe(src []byte) []byte {
    if r.AccessMask.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return r.UnmarshalBytes(src)
}

func (r *RS_SHARE_POLICY) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.AccessMask.Packed() {
        buf := cc.CopyScratchBuffer(r.SizeBytes())
        r.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RS_SHARE_POLICY) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RS_SHARE_POLICY) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.AccessMask.Packed() {
        buf := cc.CopyScratchBuffer(r.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        r.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RS_SHARE_POLICY) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RS_SHARE_POLICY) WriteTo(writer io.Writer) (int64, error) {
    if !r.AccessMask.Packed() {
        buf := make([]byte, r.SizeBytes())
        r.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) SizeBytes() int {
    return 28 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS +
        1*4
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) SizeBytes() int {
    return 28 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS_V2 +
        1*4
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_ALLOC_SEMAPHORE_POOL_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) Packed() bool {
    return true
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_CREATE_EXTERNAL_RANGE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_CREATE_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_CREATE_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_DESTROY_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes() +
        (*NvUUID)(nil).SizeBytes()
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUIDA.MarshalUnsafe(dst)
    dst = p.GPUUUIDB.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUIDA.UnmarshalUnsafe(src)
    src = p.GPUUUIDB.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) Packed() bool {
    return p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed()
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_DISABLE_PEER_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) Packed() bool {
    return true
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_DISABLE_READ_DUPLICATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes() +
        (*NvUUID)(nil).SizeBytes()
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUIDA.MarshalUnsafe(dst)
    dst = p.GPUUUIDB.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUIDA.UnmarshalUnsafe(src)
    src = p.GPUUUIDB.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) Packed() bool {
    return p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed()
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_ENABLE_PEER_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUIDA.Packed() && p.GPUUUIDB.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) Packed() bool {
    return true
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_ENABLE_READ_DUPLICATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_FREE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

func (p *UVM_FREE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_FREE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_FREE_PARAMS) Packed() bool {
    return true
}

func (p *UVM_FREE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_FREE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_FREE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_FREE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_FREE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_FREE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_FREE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_FREE_PARAMS_V590) SizeBytes() int {
    return 12 +
        1*4
}

func (p *UVM_FREE_PARAMS_V590) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_FREE_PARAMS_V590) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_FREE_PARAMS_V590) Packed() bool {
    return true
}

func (p *UVM_FREE_PARAMS_V590) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_FREE_PARAMS_V590) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_FREE_PARAMS_V590) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_FREE_PARAMS_V590) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_FREE_PARAMS_V590) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_FREE_PARAMS_V590) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_FREE_PARAMS_V590) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_INITIALIZE_PARAMS) SizeBytes() int {
    return 12 +
        1*4
}

func (p *UVM_INITIALIZE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_INITIALIZE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_INITIALIZE_PARAMS) Packed() bool {
    return true
}

func (p *UVM_INITIALIZE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_INITIALIZE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_INITIALIZE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_INITIALIZE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_INITIALIZE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_INITIALIZE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_INITIALIZE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) SizeBytes() int {
    return 48 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offset))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HClient))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HMemory))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HClient = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HMemory = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) SizeBytes() int {
    return 48 +
        (*UvmGpuMappingAttributes)(nil).SizeBytes()*UVM_MAX_GPUS_V2
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Offset))
    dst = dst[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        dst = p.PerGPUAttributes[idx].MarshalUnsafe(dst)
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.GPUAttributesCount))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HClient))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.HMemory))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < UVM_MAX_GPUS_V2; idx++ {
        src = p.PerGPUAttributes[idx].UnmarshalUnsafe(src)
    }
    p.GPUAttributesCount = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HClient = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.HMemory = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) Packed() bool {
    return p.PerGPUAttributes[0].Packed()
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.PerGPUAttributes[0].Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.PerGPUAttributes[0].Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MIGRATE_PARAMS) SizeBytes() int {
    return 56 +
        (*NvUUID)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (p *UVM_MIGRATE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.DestinationUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Flags))
    dst = dst[4:]
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.SemaphoreAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.SemaphorePayload))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.CPUNumaNode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceStart))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceLength))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    dst = dst[1*(4):]
    return dst
}

func (p *UVM_MIGRATE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.DestinationUUID.UnmarshalUnsafe(src)
    p.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    p.SemaphoreAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.SemaphorePayload = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.CPUNumaNode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.UserSpaceStart = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.UserSpaceLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MIGRATE_PARAMS) Packed() bool {
    return p.DestinationUUID.Packed()
}

func (p *UVM_MIGRATE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_MIGRATE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_MIGRATE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MIGRATE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MIGRATE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MIGRATE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MIGRATE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.DestinationUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MIGRATE_PARAMS_V550) SizeBytes() int {
    return 56 +
        (*NvUUID)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (p *UVM_MIGRATE_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.DestinationUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.Flags))
    dst = dst[4:]
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.SemaphoreAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.SemaphorePayload))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.CPUNumaNode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceStart))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.UserSpaceLength))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    dst = dst[1*(4):]
    return dst
}

func (p *UVM_MIGRATE_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.DestinationUUID.UnmarshalUnsafe(src)
    p.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    p.SemaphoreAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.SemaphorePayload = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.CPUNumaNode = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.UserSpaceStart = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.UserSpaceLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MIGRATE_PARAMS_V550) Packed() bool {
    return p.DestinationUUID.Packed()
}

func (p *UVM_MIGRATE_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_MIGRATE_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_MIGRATE_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MIGRATE_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MIGRATE_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MIGRATE_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MIGRATE_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.DestinationUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 12 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    dst = p.DestinationUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.DestinationUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) Packed() bool {
    return p.DestinationUUID.Packed()
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.DestinationUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.DestinationUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MIGRATE_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.DestinationUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_MM_INITIALIZE_PARAMS) SizeBytes() int {
    return 8
}

func (p *UVM_MM_INITIALIZE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.UvmFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_MM_INITIALIZE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.UvmFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_MM_INITIALIZE_PARAMS) Packed() bool {
    return true
}

func (p *UVM_MM_INITIALIZE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_MM_INITIALIZE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_MM_INITIALIZE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MM_INITIALIZE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_MM_INITIALIZE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_MM_INITIALIZE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_MM_INITIALIZE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) SizeBytes() int {
    return 5 +
        (*NvUUID)(nil).SizeBytes() +
        1*3
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    dst[0] = byte(p.PageableMemAccess)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.PageableMemAccess = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_PAGEABLE_MEM_ACCESS_ON_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) SizeBytes() int {
    return 5 +
        1*3
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(p.PageableMemAccess)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.PageableMemAccess = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) Packed() bool {
    return true
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_PAGEABLE_MEM_ACCESS_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) SizeBytes() int {
    return 24 +
        (*NvUUID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        1*4 +
        1*4
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HChannel.MarshalUnsafe(dst)
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HChannel.UnmarshalUnsafe(src)
    for idx := 0; idx < 4; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_REGISTER_CHANNEL_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed()
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_REGISTER_CHANNEL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_REGISTER_GPU_PARAMS) SizeBytes() int {
    return 13 +
        (*NvUUID)(nil).SizeBytes() +
        1*3 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *UVM_REGISTER_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    dst[0] = byte(p.NumaEnabled)
    dst = dst[1:]
    for idx := 0; idx < 3; idx++ {
        dst[0] = byte(p.Pad[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.NumaNodeID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HSMCPartRef.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_REGISTER_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.NumaEnabled = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < 3; idx++ {
        p.Pad[idx] = src[0]
        src = src[1:]
    }
    p.NumaNodeID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HSMCPartRef.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_REGISTER_GPU_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed()
}

func (p *UVM_REGISTER_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_REGISTER_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_REGISTER_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_REGISTER_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_REGISTER_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_REGISTER_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_REGISTER_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HSMCPartRef.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) SizeBytes() int {
    return 8 +
        (*NvUUID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMCtrlFD))
    dst = dst[4:]
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HVASpace.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMCtrlFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HVASpace.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed()
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_REGISTER_GPU_VASPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HClient.Packed() && p.HVASpace.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.AccessedByUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.AccessedByUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_ACCESSED_BY_PARAMS) Packed() bool {
    return p.AccessedByUUID.Packed()
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.AccessedByUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.AccessedByUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.AccessedByUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.AccessedByUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_ACCESSED_BY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.AccessedByUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.PreferredLocation.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.PreferredLocation.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) Packed() bool {
    return p.PreferredLocation.Packed()
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.PreferredLocation.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) SizeBytes() int {
    return 24 +
        (*NvUUID)(nil).SizeBytes()
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.PreferredLocation.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.PreferredCPUNumaNode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.PreferredLocation.UnmarshalUnsafe(src)
    p.PreferredCPUNumaNode = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) Packed() bool {
    return p.PreferredLocation.Packed()
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) MarshalUnsafe(dst []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) UnmarshalUnsafe(src []byte) []byte {
    if p.PreferredLocation.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.PreferredLocation.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_PREFERRED_LOCATION_PARAMS_V550) WriteTo(writer io.Writer) (int64, error) {
    if !p.PreferredLocation.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) SizeBytes() int {
    return 28 +
        1*4
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RangeGroupID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RangeGroupID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_SET_RANGE_GROUP_PARAMS) Packed() bool {
    return true
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_SET_RANGE_GROUP_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) SizeBytes() int {
    return 36 +
        1*4
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Buffer))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.TargetVA))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.BytesRead))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Buffer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.TargetVA = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.BytesRead = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) Packed() bool {
    return true
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_TOOLS_READ_PROCESS_MEMORY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) SizeBytes() int {
    return 36 +
        1*4
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Buffer))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.TargetVA))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.BytesWritten))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Buffer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.TargetVA = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.BytesWritten = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) Packed() bool {
    return true
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_TOOLS_WRITE_PROCESS_MEMORY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNMAP_EXTERNAL_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNMAP_EXTERNAL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HChannel.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HChannel.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_CHANNEL_PARAMS) Packed() bool {
    return p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed()
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() && p.HChannel.Packed() && p.HClient.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) SizeBytes() int {
    return 4 +
        (*Handle)(nil).SizeBytes() +
        (*Handle)(nil).SizeBytes()
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) MarshalBytes(dst []byte) []byte {
    dst = p.HClient.MarshalUnsafe(dst)
    dst = p.HChannel.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) UnmarshalBytes(src []byte) []byte {
    src = p.HClient.UnmarshalUnsafe(src)
    src = p.HChannel.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) Packed() bool {
    return p.HChannel.Packed() && p.HClient.Packed()
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) MarshalUnsafe(dst []byte) []byte {
    if p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) UnmarshalUnsafe(src []byte) []byte {
    if p.HChannel.Packed() && p.HClient.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HChannel.Packed() && p.HClient.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.HChannel.Packed() && p.HClient.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_CHANNEL_PARAMS_V590) WriteTo(writer io.Writer) (int64, error) {
    if !p.HChannel.Packed() && p.HClient.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNREGISTER_GPU_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes()
}

func (p *UVM_UNREGISTER_GPU_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_UNREGISTER_GPU_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_GPU_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

func (p *UVM_UNREGISTER_GPU_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_UNREGISTER_GPU_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_UNREGISTER_GPU_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_GPU_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_GPU_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_GPU_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_GPU_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) SizeBytes() int {
    return 4 +
        (*NvUUID)(nil).SizeBytes()
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) MarshalBytes(dst []byte) []byte {
    dst = p.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    return dst
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) UnmarshalBytes(src []byte) []byte {
    src = p.GPUUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) Packed() bool {
    return p.GPUUUID.Packed()
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.GPUUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNREGISTER_GPU_VASPACE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.GPUUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes() +
        1*4
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    dst = p.AccessedByUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = p.AccessedByUUID.UnmarshalUnsafe(src)
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNSET_ACCESSED_BY_PARAMS) Packed() bool {
    return p.AccessedByUUID.Packed()
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) MarshalUnsafe(dst []byte) []byte {
    if p.AccessedByUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
        return dst[size:]
    }
    return p.MarshalBytes(dst)
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    if p.AccessedByUUID.Packed() {
        size := p.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return p.UnmarshalBytes(src)
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.AccessedByUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        p.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !p.AccessedByUUID.Packed() {
        buf := cc.CopyScratchBuffer(p.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        p.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNSET_ACCESSED_BY_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    if !p.AccessedByUUID.Packed() {
        buf := make([]byte, p.SizeBytes())
        p.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.RequestedBase))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.RequestedBase = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) Packed() bool {
    return true
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_UNSET_PREFERRED_LOCATION_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) SizeBytes() int {
    return 20 +
        1*4
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.RMStatus))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(p.Pad0[idx])
        dst = dst[1:]
    }
    return dst
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) UnmarshalBytes(src []byte) []byte {
    p.Base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.RMStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        p.Pad0[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *UVM_VALIDATE_VA_RANGE_PARAMS) Packed() bool {
    return true
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *UVM_VALIDATE_VA_RANGE_PARAMS) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (u *UvmGpuMappingAttributes) SizeBytes() int {
    return 20 +
        (*NvUUID)(nil).SizeBytes()
}

func (u *UvmGpuMappingAttributes) MarshalBytes(dst []byte) []byte {
    dst = u.GPUUUID.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUMappingType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUCachingType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUFormatType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUElementBits))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(u.GPUCompressionType))
    dst = dst[4:]
    return dst
}

func (u *UvmGpuMappingAttributes) UnmarshalBytes(src []byte) []byte {
    src = u.GPUUUID.UnmarshalUnsafe(src)
    u.GPUMappingType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUCachingType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUFormatType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUElementBits = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    u.GPUCompressionType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UvmGpuMappingAttributes) Packed() bool {
    return u.GPUUUID.Packed()
}

func (u *UvmGpuMappingAttributes) MarshalUnsafe(dst []byte) []byte {
    if u.GPUUUID.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
        return dst[size:]
    }
    return u.MarshalBytes(dst)
}

func (u *UvmGpuMappingAttributes) UnmarshalUnsafe(src []byte) []byte {
    if u.GPUUUID.Packed() {
        size := u.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return u.UnmarshalBytes(src)
}

func (u *UvmGpuMappingAttributes) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(u.SizeBytes())
        u.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *UvmGpuMappingAttributes) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *UvmGpuMappingAttributes) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !u.GPUUUID.Packed() {
        buf := cc.CopyScratchBuffer(u.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        u.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *UvmGpuMappingAttributes) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *UvmGpuMappingAttributes) WriteTo(writer io.Writer) (int64, error) {
    if !u.GPUUUID.Packed() {
        buf := make([]byte, u.SizeBytes())
        u.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

