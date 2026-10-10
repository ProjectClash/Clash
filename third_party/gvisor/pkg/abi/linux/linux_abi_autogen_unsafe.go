
package linux

import (
    "github.com/metacubex/gvisor/pkg/gohacks"
    "github.com/metacubex/gvisor/pkg/hostarch"
    "github.com/metacubex/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

var _ marshal.Marshallable = (*BPFAttrProgAttach)(nil)
var _ marshal.Marshallable = (*BPFAttrProgLoad)(nil)
var _ marshal.Marshallable = (*BPFAttrProgQuery)(nil)
var _ marshal.Marshallable = (*BPFInstruction)(nil)
var _ marshal.Marshallable = (*CString)(nil)
var _ marshal.Marshallable = (*CapUserData)(nil)
var _ marshal.Marshallable = (*CapUserHeader)(nil)
var _ marshal.Marshallable = (*ClockT)(nil)
var _ marshal.Marshallable = (*CloneArgs)(nil)
var _ marshal.Marshallable = (*ControlMessageCredentials)(nil)
var _ marshal.Marshallable = (*ControlMessageHeader)(nil)
var _ marshal.Marshallable = (*ControlMessageIPPacketInfo)(nil)
var _ marshal.Marshallable = (*ControlMessageIPv6PacketInfo)(nil)
var _ marshal.Marshallable = (*EBPFInstruction)(nil)
var _ marshal.Marshallable = (*ElfHeader64)(nil)
var _ marshal.Marshallable = (*ElfProg64)(nil)
var _ marshal.Marshallable = (*ElfSection64)(nil)
var _ marshal.Marshallable = (*ErrorName)(nil)
var _ marshal.Marshallable = (*EthtoolCmd)(nil)
var _ marshal.Marshallable = (*EthtoolGFeatures)(nil)
var _ marshal.Marshallable = (*EthtoolGetFeaturesBlock)(nil)
var _ marshal.Marshallable = (*ExtensionName)(nil)
var _ marshal.Marshallable = (*FOwnerEx)(nil)
var _ marshal.Marshallable = (*FUSEAccessIn)(nil)
var _ marshal.Marshallable = (*FUSEAttr)(nil)
var _ marshal.Marshallable = (*FUSEAttrOut)(nil)
var _ marshal.Marshallable = (*FUSECreateIn)(nil)
var _ marshal.Marshallable = (*FUSECreateMeta)(nil)
var _ marshal.Marshallable = (*FUSECreateOut)(nil)
var _ marshal.Marshallable = (*FUSEDirent)(nil)
var _ marshal.Marshallable = (*FUSEDirentMeta)(nil)
var _ marshal.Marshallable = (*FUSEDirents)(nil)
var _ marshal.Marshallable = (*FUSEEmptyIn)(nil)
var _ marshal.Marshallable = (*FUSEEntryOut)(nil)
var _ marshal.Marshallable = (*FUSEFallocateIn)(nil)
var _ marshal.Marshallable = (*FUSEFlushIn)(nil)
var _ marshal.Marshallable = (*FUSEFsyncIn)(nil)
var _ marshal.Marshallable = (*FUSEGetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSEGetXattrHdr)(nil)
var _ marshal.Marshallable = (*FUSEGetXattrIn)(nil)
var _ marshal.Marshallable = (*FUSEGetXattrOut)(nil)
var _ marshal.Marshallable = (*FUSEHeaderIn)(nil)
var _ marshal.Marshallable = (*FUSEHeaderOut)(nil)
var _ marshal.Marshallable = (*FUSEInitIn)(nil)
var _ marshal.Marshallable = (*FUSEInitOut)(nil)
var _ marshal.Marshallable = (*FUSELinkIn)(nil)
var _ marshal.Marshallable = (*FUSELookupIn)(nil)
var _ marshal.Marshallable = (*FUSEMkdirIn)(nil)
var _ marshal.Marshallable = (*FUSEMkdirMeta)(nil)
var _ marshal.Marshallable = (*FUSEMknodIn)(nil)
var _ marshal.Marshallable = (*FUSEMknodMeta)(nil)
var _ marshal.Marshallable = (*FUSEOpID)(nil)
var _ marshal.Marshallable = (*FUSEOpcode)(nil)
var _ marshal.Marshallable = (*FUSEOpenIn)(nil)
var _ marshal.Marshallable = (*FUSEOpenOut)(nil)
var _ marshal.Marshallable = (*FUSEReadIn)(nil)
var _ marshal.Marshallable = (*FUSEReleaseIn)(nil)
var _ marshal.Marshallable = (*FUSERenameIn)(nil)
var _ marshal.Marshallable = (*FUSERmDirIn)(nil)
var _ marshal.Marshallable = (*FUSESetAttrIn)(nil)
var _ marshal.Marshallable = (*FUSESetXattrHdr)(nil)
var _ marshal.Marshallable = (*FUSESetXattrIn)(nil)
var _ marshal.Marshallable = (*FUSEStatfsOut)(nil)
var _ marshal.Marshallable = (*FUSESymlinkIn)(nil)
var _ marshal.Marshallable = (*FUSEUnlinkIn)(nil)
var _ marshal.Marshallable = (*FUSEWriteIn)(nil)
var _ marshal.Marshallable = (*FUSEWriteOut)(nil)
var _ marshal.Marshallable = (*FUSEWritePayloadIn)(nil)
var _ marshal.Marshallable = (*FileMode)(nil)
var _ marshal.Marshallable = (*Flock)(nil)
var _ marshal.Marshallable = (*ICMP6Filter)(nil)
var _ marshal.Marshallable = (*IFConf)(nil)
var _ marshal.Marshallable = (*IFReq)(nil)
var _ marshal.Marshallable = (*IOCallback)(nil)
var _ marshal.Marshallable = (*IOCqRingOffsets)(nil)
var _ marshal.Marshallable = (*IOEvent)(nil)
var _ marshal.Marshallable = (*IORingIndex)(nil)
var _ marshal.Marshallable = (*IORings)(nil)
var _ marshal.Marshallable = (*IOSqRingOffsets)(nil)
var _ marshal.Marshallable = (*IOUring)(nil)
var _ marshal.Marshallable = (*IOUringCqe)(nil)
var _ marshal.Marshallable = (*IOUringParams)(nil)
var _ marshal.Marshallable = (*IOUringSqe)(nil)
var _ marshal.Marshallable = (*IP6TEntry)(nil)
var _ marshal.Marshallable = (*IP6TIP)(nil)
var _ marshal.Marshallable = (*IP6TRejectInfo)(nil)
var _ marshal.Marshallable = (*IP6TReplace)(nil)
var _ marshal.Marshallable = (*IPCPerm)(nil)
var _ marshal.Marshallable = (*IPTEntry)(nil)
var _ marshal.Marshallable = (*IPTGetEntries)(nil)
var _ marshal.Marshallable = (*IPTGetinfo)(nil)
var _ marshal.Marshallable = (*IPTIP)(nil)
var _ marshal.Marshallable = (*IPTOwnerInfo)(nil)
var _ marshal.Marshallable = (*IPTRejectInfo)(nil)
var _ marshal.Marshallable = (*IPTReplace)(nil)
var _ marshal.Marshallable = (*Inet6Addr)(nil)
var _ marshal.Marshallable = (*Inet6MulticastRequest)(nil)
var _ marshal.Marshallable = (*InetAddr)(nil)
var _ marshal.Marshallable = (*InetMulticastRequest)(nil)
var _ marshal.Marshallable = (*InetMulticastRequestWithNIC)(nil)
var _ marshal.Marshallable = (*InterfaceAddrMessage)(nil)
var _ marshal.Marshallable = (*InterfaceInfoMessage)(nil)
var _ marshal.Marshallable = (*ItimerVal)(nil)
var _ marshal.Marshallable = (*Itimerspec)(nil)
var _ marshal.Marshallable = (*KernelIP6TEntry)(nil)
var _ marshal.Marshallable = (*KernelIP6TGetEntries)(nil)
var _ marshal.Marshallable = (*KernelIPTEntry)(nil)
var _ marshal.Marshallable = (*KernelIPTGetEntries)(nil)
var _ marshal.Marshallable = (*KernelTermios)(nil)
var _ marshal.Marshallable = (*Linger)(nil)
var _ marshal.Marshallable = (*MqAttr)(nil)
var _ marshal.Marshallable = (*MsgBuf)(nil)
var _ marshal.Marshallable = (*MsgInfo)(nil)
var _ marshal.Marshallable = (*MsqidDS)(nil)
var _ marshal.Marshallable = (*NFNATRange)(nil)
var _ marshal.Marshallable = (*NFNATRange2)(nil)
var _ marshal.Marshallable = (*NetFilterGenMsg)(nil)
var _ marshal.Marshallable = (*NetlinkAttrHeader)(nil)
var _ marshal.Marshallable = (*NetlinkErrorMessage)(nil)
var _ marshal.Marshallable = (*NetlinkMessageHeader)(nil)
var _ marshal.Marshallable = (*NfNATIPV4MultiRangeCompat)(nil)
var _ marshal.Marshallable = (*NfNATIPV4Range)(nil)
var _ marshal.Marshallable = (*NumaPolicy)(nil)
var _ marshal.Marshallable = (*PollFD)(nil)
var _ marshal.Marshallable = (*PosixACLXattr)(nil)
var _ marshal.Marshallable = (*PosixACLXattrEntry)(nil)
var _ marshal.Marshallable = (*RSeqCriticalSection)(nil)
var _ marshal.Marshallable = (*RobustListHead)(nil)
var _ marshal.Marshallable = (*RouteMessage)(nil)
var _ marshal.Marshallable = (*RtAttr)(nil)
var _ marshal.Marshallable = (*Rusage)(nil)
var _ marshal.Marshallable = (*SchedAttr)(nil)
var _ marshal.Marshallable = (*SeccompData)(nil)
var _ marshal.Marshallable = (*SeccompNotif)(nil)
var _ marshal.Marshallable = (*SeccompNotifResp)(nil)
var _ marshal.Marshallable = (*SeccompNotifSizes)(nil)
var _ marshal.Marshallable = (*SemInfo)(nil)
var _ marshal.Marshallable = (*Sembuf)(nil)
var _ marshal.Marshallable = (*ShmInfo)(nil)
var _ marshal.Marshallable = (*ShmParams)(nil)
var _ marshal.Marshallable = (*ShmidDS)(nil)
var _ marshal.Marshallable = (*SigAction)(nil)
var _ marshal.Marshallable = (*Sigevent)(nil)
var _ marshal.Marshallable = (*SignalInfo)(nil)
var _ marshal.Marshallable = (*SignalSet)(nil)
var _ marshal.Marshallable = (*SignalStack)(nil)
var _ marshal.Marshallable = (*SignalfdSiginfo)(nil)
var _ marshal.Marshallable = (*SockAddrInet)(nil)
var _ marshal.Marshallable = (*SockAddrInet6)(nil)
var _ marshal.Marshallable = (*SockAddrLink)(nil)
var _ marshal.Marshallable = (*SockAddrNetlink)(nil)
var _ marshal.Marshallable = (*SockAddrUnix)(nil)
var _ marshal.Marshallable = (*SockErrCMsgIPv4)(nil)
var _ marshal.Marshallable = (*SockErrCMsgIPv6)(nil)
var _ marshal.Marshallable = (*SockExtendedErr)(nil)
var _ marshal.Marshallable = (*Statfs)(nil)
var _ marshal.Marshallable = (*Statx)(nil)
var _ marshal.Marshallable = (*StatxTimestamp)(nil)
var _ marshal.Marshallable = (*Sysinfo)(nil)
var _ marshal.Marshallable = (*TCPInfo)(nil)
var _ marshal.Marshallable = (*TableName)(nil)
var _ marshal.Marshallable = (*Termios)(nil)
var _ marshal.Marshallable = (*TimeT)(nil)
var _ marshal.Marshallable = (*TimerID)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)
var _ marshal.Marshallable = (*Timeval)(nil)
var _ marshal.Marshallable = (*Tms)(nil)
var _ marshal.Marshallable = (*Tpacket2Hdr)(nil)
var _ marshal.Marshallable = (*TpacketHdr)(nil)
var _ marshal.Marshallable = (*TpacketReq)(nil)
var _ marshal.Marshallable = (*TpacketStats)(nil)
var _ marshal.Marshallable = (*Utime)(nil)
var _ marshal.Marshallable = (*UtsName)(nil)
var _ marshal.Marshallable = (*VFIODeviceInfo)(nil)
var _ marshal.Marshallable = (*VFIODeviceInfoMin)(nil)
var _ marshal.Marshallable = (*VFIOIommuType1DmaMap)(nil)
var _ marshal.Marshallable = (*VFIOIommuType1DmaUnmap)(nil)
var _ marshal.Marshallable = (*VFIOIrqInfo)(nil)
var _ marshal.Marshallable = (*VFIOIrqSet)(nil)
var _ marshal.Marshallable = (*VFIORegionInfo)(nil)
var _ marshal.Marshallable = (*VfsCapData)(nil)
var _ marshal.Marshallable = (*VfsNsCapData)(nil)
var _ marshal.Marshallable = (*Winsize)(nil)
var _ marshal.Marshallable = (*XTCTTargetInfoV0)(nil)
var _ marshal.Marshallable = (*XTCounters)(nil)
var _ marshal.Marshallable = (*XTEntryMatch)(nil)
var _ marshal.Marshallable = (*XTEntryTarget)(nil)
var _ marshal.Marshallable = (*XTErrorTarget)(nil)
var _ marshal.Marshallable = (*XTGetRevision)(nil)
var _ marshal.Marshallable = (*XTMarkMtinfo1)(nil)
var _ marshal.Marshallable = (*XTMultiport)(nil)
var _ marshal.Marshallable = (*XTMultiportV1)(nil)
var _ marshal.Marshallable = (*XTNATTargetV0)(nil)
var _ marshal.Marshallable = (*XTNATTargetV1)(nil)
var _ marshal.Marshallable = (*XTNATTargetV2)(nil)
var _ marshal.Marshallable = (*XTOwnerMatchInfo)(nil)
var _ marshal.Marshallable = (*XTRedirectTarget)(nil)
var _ marshal.Marshallable = (*XTStandardTarget)(nil)
var _ marshal.Marshallable = (*XTTCP)(nil)
var _ marshal.Marshallable = (*XTUDP)(nil)

func (i *IOCallback) SizeBytes() int {
    return 64
}

func (i *IOCallback) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Data))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Key))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.OpCode))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.ReqPrio))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Buf))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Bytes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Reserved2))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ResFD))
    dst = dst[4:]
    return dst
}

func (i *IOCallback) UnmarshalBytes(src []byte) []byte {
    i.Data = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Key = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    i.OpCode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.ReqPrio = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Buf = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Bytes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Offset = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Reserved2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.ResFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOCallback) Packed() bool {
    return true
}

func (i *IOCallback) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOCallback) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOCallback) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOCallback) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOCallback) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOCallback) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOCallback) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IOEvent) SizeBytes() int {
    return 32
}

func (i *IOEvent) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Data))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Obj))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Result))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Result2))
    dst = dst[8:]
    return dst
}

func (i *IOEvent) UnmarshalBytes(src []byte) []byte {
    i.Data = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Obj = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Result = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Result2 = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOEvent) Packed() bool {
    return true
}

func (i *IOEvent) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOEvent) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOEvent) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (b *BPFInstruction) SizeBytes() int {
    return 8
}

func (b *BPFInstruction) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(b.OpCode))
    dst = dst[2:]
    dst[0] = byte(b.JumpIfTrue)
    dst = dst[1:]
    dst[0] = byte(b.JumpIfFalse)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(b.K))
    dst = dst[4:]
    return dst
}

func (b *BPFInstruction) UnmarshalBytes(src []byte) []byte {
    b.OpCode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    b.JumpIfTrue = uint8(src[0])
    src = src[1:]
    b.JumpIfFalse = uint8(src[0])
    src = src[1:]
    b.K = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (b *BPFInstruction) Packed() bool {
    return true
}

func (b *BPFInstruction) MarshalUnsafe(dst []byte) []byte {
    size := b.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(b), uintptr(size))
    return dst[size:]
}

func (b *BPFInstruction) UnmarshalUnsafe(src []byte) []byte {
    size := b.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(b), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (b *BPFInstruction) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(b)
    return length, err
}

func (b *BPFInstruction) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyOutN(cc, addr, b.SizeBytes())
}

func (b *BPFInstruction) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(b)
    return length, err
}

func (b *BPFInstruction) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyInN(cc, addr, b.SizeBytes())
}

func (b *BPFInstruction) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(b)))
    hdr.Len = b.SizeBytes()
    hdr.Cap = b.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(b)
    return int64(length), err
}

func CopyBPFInstructionSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []BPFInstruction) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyBPFInstructionSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []BPFInstruction) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeBPFInstructionSlice(src []BPFInstruction, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*BPFInstruction)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeBPFInstructionSlice(dst []BPFInstruction, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*BPFInstruction)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadBPFInstructionSlice(src io.Reader, dst []BPFInstruction) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteBPFInstructionSlice(dst io.Writer, src []BPFInstruction) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*BPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (c *CapUserData) SizeBytes() int {
    return 12
}

func (c *CapUserData) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Effective))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Permitted))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Inheritable))
    dst = dst[4:]
    return dst
}

func (c *CapUserData) UnmarshalBytes(src []byte) []byte {
    c.Effective = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Permitted = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Inheritable = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CapUserData) Packed() bool {
    return true
}

func (c *CapUserData) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *CapUserData) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *CapUserData) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *CapUserData) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *CapUserData) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *CapUserData) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *CapUserData) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func CopyCapUserDataSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []CapUserData) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyCapUserDataSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []CapUserData) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeCapUserDataSlice(src []CapUserData, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*CapUserData)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeCapUserDataSlice(dst []CapUserData, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*CapUserData)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadCapUserDataSlice(src io.Reader, dst []CapUserData) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteCapUserDataSlice(dst io.Writer, src []CapUserData) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*CapUserData)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (c *CapUserHeader) SizeBytes() int {
    return 8
}

func (c *CapUserHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Pid))
    dst = dst[4:]
    return dst
}

func (c *CapUserHeader) UnmarshalBytes(src []byte) []byte {
    c.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Pid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CapUserHeader) Packed() bool {
    return true
}

func (c *CapUserHeader) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *CapUserHeader) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *CapUserHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *CapUserHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *CapUserHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *CapUserHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *CapUserHeader) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (c *VfsCapData) SizeBytes() int {
    return 20
}

func (c *VfsCapData) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.MagicEtc))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.PermittedLo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.InheritableLo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.PermittedHi))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.InheritableHi))
    dst = dst[4:]
    return dst
}

func (c *VfsCapData) UnmarshalBytes(src []byte) []byte {
    c.MagicEtc = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.PermittedLo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.InheritableLo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.PermittedHi = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.InheritableHi = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *VfsCapData) Packed() bool {
    return true
}

func (c *VfsCapData) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *VfsCapData) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *VfsCapData) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *VfsCapData) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *VfsCapData) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *VfsCapData) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *VfsCapData) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (c *VfsNsCapData) SizeBytes() int {
    return 4 +
        (*VfsCapData)(nil).SizeBytes()
}

func (c *VfsNsCapData) MarshalBytes(dst []byte) []byte {
    dst = c.VfsCapData.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.RootID))
    dst = dst[4:]
    return dst
}

func (c *VfsNsCapData) UnmarshalBytes(src []byte) []byte {
    src = c.VfsCapData.UnmarshalUnsafe(src)
    c.RootID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *VfsNsCapData) Packed() bool {
    return c.VfsCapData.Packed()
}

func (c *VfsNsCapData) MarshalUnsafe(dst []byte) []byte {
    if c.VfsCapData.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    return c.MarshalBytes(dst)
}

func (c *VfsNsCapData) UnmarshalUnsafe(src []byte) []byte {
    if c.VfsCapData.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return c.UnmarshalBytes(src)
}

func (c *VfsNsCapData) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.VfsCapData.Packed() {
        buf := cc.CopyScratchBuffer(c.SizeBytes())
        c.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *VfsNsCapData) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *VfsNsCapData) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.VfsCapData.Packed() {
        buf := cc.CopyScratchBuffer(c.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        c.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *VfsNsCapData) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *VfsNsCapData) WriteTo(writer io.Writer) (int64, error) {
    if !c.VfsCapData.Packed() {
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (c *CloneArgs) SizeBytes() int {
    return 88
}

func (c *CloneArgs) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Pidfd))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.ChildTID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.ParentTID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.ExitSignal))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Stack))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.StackSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.TLS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.SetTID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.SetTIDSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Cgroup))
    dst = dst[8:]
    return dst
}

func (c *CloneArgs) UnmarshalBytes(src []byte) []byte {
    c.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Pidfd = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.ChildTID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.ParentTID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.ExitSignal = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Stack = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.StackSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.TLS = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.SetTID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.SetTIDSize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Cgroup = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *CloneArgs) Packed() bool {
    return true
}

func (c *CloneArgs) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *CloneArgs) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *CloneArgs) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *CloneArgs) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *CloneArgs) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *CloneArgs) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *CloneArgs) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (a *BPFAttrProgAttach) SizeBytes() int {
    return 32
}

func (a *BPFAttrProgAttach) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Target))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachBPFFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ReplaceBPFFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Relative))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.ExpectedRevision))
    dst = dst[8:]
    return dst
}

func (a *BPFAttrProgAttach) UnmarshalBytes(src []byte) []byte {
    a.Target = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachBPFFD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ReplaceBPFFD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Relative = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ExpectedRevision = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *BPFAttrProgAttach) Packed() bool {
    return true
}

func (a *BPFAttrProgAttach) MarshalUnsafe(dst []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(a), uintptr(size))
    return dst[size:]
}

func (a *BPFAttrProgAttach) UnmarshalUnsafe(src []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(a), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (a *BPFAttrProgAttach) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *BPFAttrProgAttach) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

func (a *BPFAttrProgAttach) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *BPFAttrProgAttach) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

func (a *BPFAttrProgAttach) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(a)
    return int64(length), err
}

func (a *BPFAttrProgLoad) SizeBytes() int {
    return 152 +
        1*BPF_OBJ_NAME_LEN
}

func (a *BPFAttrProgLoad) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ProgType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.InstructionCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Instructions))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.License))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.LogLevel))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.LogSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.LogBuf))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.KernVersion))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ProgFlags))
    dst = dst[4:]
    for idx := 0; idx < BPF_OBJ_NAME_LEN; idx++ {
        dst[0] = byte(a.ProgName[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ProgInterfaceIndex))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ExpectedAttachType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ProgBTFFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.FuncInfoRecSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.FuncInfo))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.FuncInfoCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.LineInfoRecSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.LineInfo))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.LineInfoCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachBTFID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.CoreReloCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.FDArray))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.CoreRelos))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.CoreReloRecSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.LogTrueSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.ProgTokenFD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.FDArrayCount))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Signature))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.SignatureSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.KeyringID))
    dst = dst[4:]
    return dst
}

func (a *BPFAttrProgLoad) UnmarshalBytes(src []byte) []byte {
    a.ProgType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.InstructionCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Instructions = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.License = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.LogLevel = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.LogSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.LogBuf = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.KernVersion = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ProgFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < BPF_OBJ_NAME_LEN; idx++ {
        a.ProgName[idx] = src[0]
        src = src[1:]
    }
    a.ProgInterfaceIndex = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ExpectedAttachType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ProgBTFFD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.FuncInfoRecSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.FuncInfo = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.FuncInfoCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.LineInfoRecSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.LineInfo = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.LineInfoCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachBTFID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachFD = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.CoreReloCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.FDArray = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.CoreRelos = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.CoreReloRecSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.LogTrueSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ProgTokenFD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.FDArrayCount = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Signature = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.SignatureSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.KeyringID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *BPFAttrProgLoad) Packed() bool {
    return true
}

func (a *BPFAttrProgLoad) MarshalUnsafe(dst []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(a), uintptr(size))
    return dst[size:]
}

func (a *BPFAttrProgLoad) UnmarshalUnsafe(src []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(a), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (a *BPFAttrProgLoad) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *BPFAttrProgLoad) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

func (a *BPFAttrProgLoad) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *BPFAttrProgLoad) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

func (a *BPFAttrProgLoad) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(a)
    return int64(length), err
}

func (a *BPFAttrProgQuery) SizeBytes() int {
    return 64
}

func (a *BPFAttrProgQuery) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Target))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachType))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.QueryFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AttachFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.ProgIDs))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Count))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.ProgAttachFlags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.LinkIDs))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.LinkAttachFlags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Revision))
    dst = dst[8:]
    return dst
}

func (a *BPFAttrProgQuery) UnmarshalBytes(src []byte) []byte {
    a.Target = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachType = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.QueryFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.AttachFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.ProgIDs = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Count = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    a.ProgAttachFlags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.LinkIDs = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.LinkAttachFlags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Revision = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *BPFAttrProgQuery) Packed() bool {
    return true
}

func (a *BPFAttrProgQuery) MarshalUnsafe(dst []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(a), uintptr(size))
    return dst[size:]
}

func (a *BPFAttrProgQuery) UnmarshalUnsafe(src []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(a), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (a *BPFAttrProgQuery) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *BPFAttrProgQuery) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

func (a *BPFAttrProgQuery) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *BPFAttrProgQuery) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

func (a *BPFAttrProgQuery) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(a)
    return int64(length), err
}

func (e *EBPFInstruction) SizeBytes() int {
    return 8
}

func (e *EBPFInstruction) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(e.Code)
    dst = dst[1:]
    dst[0] = byte(e.Registers)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Offset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Immediate))
    dst = dst[4:]
    return dst
}

func (e *EBPFInstruction) UnmarshalBytes(src []byte) []byte {
    e.Code = uint8(src[0])
    src = src[1:]
    e.Registers = uint8(src[0])
    src = src[1:]
    e.Offset = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Immediate = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EBPFInstruction) Packed() bool {
    return true
}

func (e *EBPFInstruction) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *EBPFInstruction) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *EBPFInstruction) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EBPFInstruction) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *EBPFInstruction) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EBPFInstruction) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *EBPFInstruction) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func CopyEBPFInstructionSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []EBPFInstruction) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*EBPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyEBPFInstructionSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []EBPFInstruction) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*EBPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeEBPFInstructionSlice(src []EBPFInstruction, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*EBPFInstruction)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeEBPFInstructionSlice(dst []EBPFInstruction, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*EBPFInstruction)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadEBPFInstructionSlice(src io.Reader, dst []EBPFInstruction) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*EBPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteEBPFInstructionSlice(dst io.Writer, src []EBPFInstruction) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*EBPFInstruction)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (e *ElfHeader64) SizeBytes() int {
    return 48 +
        1*16
}

func (e *ElfHeader64) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(e.Ident[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Machine))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Entry))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Phoff))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Shoff))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Ehsize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Phentsize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Phnum))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Shentsize))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Shnum))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(e.Shstrndx))
    dst = dst[2:]
    return dst
}

func (e *ElfHeader64) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        e.Ident[idx] = src[0]
        src = src[1:]
    }
    e.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Machine = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Entry = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Phoff = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Shoff = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Ehsize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Phentsize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Phnum = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Shentsize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Shnum = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    e.Shstrndx = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ElfHeader64) Packed() bool {
    return true
}

func (e *ElfHeader64) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *ElfHeader64) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *ElfHeader64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *ElfHeader64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *ElfHeader64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *ElfHeader64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *ElfHeader64) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func (e *ElfProg64) SizeBytes() int {
    return 56
}

func (e *ElfProg64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Off))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Vaddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Paddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Filesz))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Memsz))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Align))
    dst = dst[8:]
    return dst
}

func (e *ElfProg64) UnmarshalBytes(src []byte) []byte {
    e.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Off = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Vaddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Paddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Filesz = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Memsz = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Align = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ElfProg64) Packed() bool {
    return true
}

func (e *ElfProg64) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *ElfProg64) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *ElfProg64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *ElfProg64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *ElfProg64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *ElfProg64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *ElfProg64) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func (e *ElfSection64) SizeBytes() int {
    return 64
}

func (e *ElfSection64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Name))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Off))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Link))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Info))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Addralign))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(e.Entsize))
    dst = dst[8:]
    return dst
}

func (e *ElfSection64) UnmarshalBytes(src []byte) []byte {
    e.Name = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Off = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Link = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Info = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Addralign = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    e.Entsize = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *ElfSection64) Packed() bool {
    return true
}

func (e *ElfSection64) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *ElfSection64) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *ElfSection64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *ElfSection64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *ElfSection64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *ElfSection64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *ElfSection64) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func (s *SockErrCMsgIPv4) SizeBytes() int {
    return 0 +
        (*SockExtendedErr)(nil).SizeBytes() +
        (*SockAddrInet)(nil).SizeBytes()
}

func (s *SockErrCMsgIPv4) MarshalBytes(dst []byte) []byte {
    dst = s.SockExtendedErr.MarshalUnsafe(dst)
    dst = s.Offender.MarshalUnsafe(dst)
    return dst
}

func (s *SockErrCMsgIPv4) UnmarshalBytes(src []byte) []byte {
    src = s.SockExtendedErr.UnmarshalUnsafe(src)
    src = s.Offender.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockErrCMsgIPv4) Packed() bool {
    return s.Offender.Packed() && s.SockExtendedErr.Packed()
}

func (s *SockErrCMsgIPv4) MarshalUnsafe(dst []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *SockErrCMsgIPv4) UnmarshalUnsafe(src []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *SockErrCMsgIPv4) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockErrCMsgIPv4) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockErrCMsgIPv4) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockErrCMsgIPv4) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockErrCMsgIPv4) WriteTo(writer io.Writer) (int64, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SockErrCMsgIPv6) SizeBytes() int {
    return 0 +
        (*SockExtendedErr)(nil).SizeBytes() +
        (*SockAddrInet6)(nil).SizeBytes()
}

func (s *SockErrCMsgIPv6) MarshalBytes(dst []byte) []byte {
    dst = s.SockExtendedErr.MarshalUnsafe(dst)
    dst = s.Offender.MarshalUnsafe(dst)
    return dst
}

func (s *SockErrCMsgIPv6) UnmarshalBytes(src []byte) []byte {
    src = s.SockExtendedErr.UnmarshalUnsafe(src)
    src = s.Offender.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockErrCMsgIPv6) Packed() bool {
    return s.Offender.Packed() && s.SockExtendedErr.Packed()
}

func (s *SockErrCMsgIPv6) MarshalUnsafe(dst []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *SockErrCMsgIPv6) UnmarshalUnsafe(src []byte) []byte {
    if s.Offender.Packed() && s.SockExtendedErr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *SockErrCMsgIPv6) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockErrCMsgIPv6) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockErrCMsgIPv6) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockErrCMsgIPv6) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockErrCMsgIPv6) WriteTo(writer io.Writer) (int64, error) {
    if !s.Offender.Packed() && s.SockExtendedErr.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SockExtendedErr) SizeBytes() int {
    return 16
}

func (s *SockExtendedErr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    dst[0] = byte(s.Origin)
    dst = dst[1:]
    dst[0] = byte(s.Type)
    dst = dst[1:]
    dst[0] = byte(s.Code)
    dst = dst[1:]
    dst[0] = byte(s.Pad)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Info))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Data))
    dst = dst[4:]
    return dst
}

func (s *SockExtendedErr) UnmarshalBytes(src []byte) []byte {
    s.Errno = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Origin = uint8(src[0])
    src = src[1:]
    s.Type = uint8(src[0])
    src = src[1:]
    s.Code = uint8(src[0])
    src = src[1:]
    s.Pad = uint8(src[0])
    src = src[1:]
    s.Info = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Data = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockExtendedErr) Packed() bool {
    return true
}

func (s *SockExtendedErr) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SockExtendedErr) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SockExtendedErr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockExtendedErr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockExtendedErr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockExtendedErr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockExtendedErr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (f *FOwnerEx) SizeBytes() int {
    return 8
}

func (f *FOwnerEx) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Type))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    return dst
}

func (f *FOwnerEx) UnmarshalBytes(src []byte) []byte {
    f.Type = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FOwnerEx) Packed() bool {
    return true
}

func (f *FOwnerEx) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FOwnerEx) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FOwnerEx) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FOwnerEx) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FOwnerEx) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FOwnerEx) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FOwnerEx) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *Flock) SizeBytes() int {
    return 24 +
        1*4 +
        1*4
}

func (f *Flock) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.Whence))
    dst = dst[2:]
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Start))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Len))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    dst = dst[1*(4):]
    return dst
}

func (f *Flock) UnmarshalBytes(src []byte) []byte {
    f.Type = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.Whence = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(4):]
    f.Start = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Len = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.PID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *Flock) Packed() bool {
    return true
}

func (f *Flock) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *Flock) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *Flock) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *Flock) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *Flock) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *Flock) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *Flock) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (m *FileMode) SizeBytes() int {
    return 2
}

func (m *FileMode) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(*m))
    return dst[2:]
}

func (m *FileMode) UnmarshalBytes(src []byte) []byte {
    *m = FileMode(uint16(hostarch.ByteOrder.Uint16(src[:2])))
    return src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *FileMode) Packed() bool {
    return true
}

func (m *FileMode) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

func (m *FileMode) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (m *FileMode) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(m)
    return length, err
}

func (m *FileMode) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

func (m *FileMode) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(m)
    return length, err
}

func (m *FileMode) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

func (m *FileMode) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(m)
    return int64(length), err
}

func (s *Statx) SizeBytes() int {
    return 88 +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes() +
        (*StatxTimestamp)(nil).SizeBytes()
}

func (s *Statx) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Mask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Blksize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Attributes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Nlink))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Mode))
    dst = dst[2:]
    dst = dst[2:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.AttributesMask))
    dst = dst[8:]
    dst = s.Atime.MarshalUnsafe(dst)
    dst = s.Btime.MarshalUnsafe(dst)
    dst = s.Ctime.MarshalUnsafe(dst)
    dst = s.Mtime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMajor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.RdevMinor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.DevMajor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.DevMinor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.MntID))
    dst = dst[8:]
    return dst
}

func (s *Statx) UnmarshalBytes(src []byte) []byte {
    s.Mask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Blksize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Attributes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nlink = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Mode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[2:]
    s.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AttributesMask = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.Atime.UnmarshalUnsafe(src)
    src = s.Btime.UnmarshalUnsafe(src)
    src = s.Ctime.UnmarshalUnsafe(src)
    src = s.Mtime.UnmarshalUnsafe(src)
    s.RdevMajor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.RdevMinor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMajor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.DevMinor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.MntID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statx) Packed() bool {
    return s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed()
}

func (s *Statx) MarshalUnsafe(dst []byte) []byte {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *Statx) UnmarshalUnsafe(src []byte) []byte {
    if s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *Statx) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Statx) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *Statx) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Statx) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *Statx) WriteTo(writer io.Writer) (int64, error) {
    if !s.Atime.Packed() && s.Btime.Packed() && s.Ctime.Packed() && s.Mtime.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *Statx) CheckedMarshal(dst []byte) ([]byte, bool) {
    if s.SizeBytes() > len(dst) {
        return dst, false
    }
    return s.MarshalUnsafe(dst), true
}

func (s *Statx) CheckedUnmarshal(src []byte) ([]byte, bool) {
    if s.SizeBytes() > len(src) {
        return src, false
    }
    return s.UnmarshalUnsafe(src), true
}

func CopyStatxSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Statx) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Statx)(nil).SizeBytes()

    if !dst[0].Packed() {
        buf := cc.CopyScratchBuffer(size * count)
        length, err := cc.CopyInBytes(addr, buf)

        limit := length/size
        for idx := 0; idx < limit; idx++ {
            buf = dst[idx].UnmarshalBytes(buf)
        }

        if length%size != 0 {
            dst[limit].UnmarshalBytes(buf)
        }

        return length, err
    }

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyStatxSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Statx) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Statx)(nil).SizeBytes()

    if !src[0].Packed() {
        buf := cc.CopyScratchBuffer(size * count)
        curBuf := buf
        for idx := 0; idx < count; idx++ {
            curBuf = src[idx].MarshalBytes(curBuf)
        }
        return cc.CopyOutBytes(addr, buf)
    }

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeStatxSlice(src []Statx, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    if !src[0].Packed() {
        for idx := 0; idx < count; idx++ {
            dst = src[idx].MarshalBytes(dst)
        }
        return dst
    }

    size := (*Statx)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeStatxSlice(dst []Statx, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    if !dst[0].Packed() {
        for idx := 0; idx < count; idx++ {
            src = dst[idx].UnmarshalBytes(src)
        }
        return src
    }

    size := (*Statx)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadStatxSlice(src io.Reader, dst []Statx) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Statx)(nil).SizeBytes()

    if !dst[0].Packed() {
        buf := make([]byte, size)
        length := 0
        for idx := 0; idx < count; idx++ {
            n, err := io.ReadFull(src, buf)
            length += n
            if err != nil {
                return length, err
            }
            dst[idx].UnmarshalBytes(buf)
        }
        return length, nil
    }

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteStatxSlice(dst io.Writer, src []Statx) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Statx)(nil).SizeBytes()

    if !src[0].Packed() {
        buf := make([]byte, size)
        length := 0
        for idx := 0; idx < count; idx++ {
            src[idx].MarshalBytes(buf)
            n, err := dst.Write(buf)
            length += n
            if err != nil {
                return length, err
            }
        }
        return length, nil
    }

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (s *Statfs) SizeBytes() int {
    return 80 +
        4*2 +
        8*4
}

func (s *Statfs) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Type))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlockSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BlocksAvailable))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Files))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FilesFree))
    dst = dst[8:]
    for idx := 0; idx < 2; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.FSID[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.NameLength))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FragmentSize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    for idx := 0; idx < 4; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Spare[idx]))
        dst = dst[8:]
    }
    return dst
}

func (s *Statfs) UnmarshalBytes(src []byte) []byte {
    s.Type = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlockSize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BlocksAvailable = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Files = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FilesFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 2; idx++ {
        s.FSID[idx] = int32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    s.NameLength = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FragmentSize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 4; idx++ {
        s.Spare[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Statfs) Packed() bool {
    return true
}

func (s *Statfs) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *Statfs) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *Statfs) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Statfs) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *Statfs) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Statfs) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *Statfs) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *CString) Packed() bool {
    return false
}

func (s *CString) MarshalUnsafe(dst []byte) []byte {
    return s.MarshalBytes(dst)
}

func (s *CString) UnmarshalUnsafe(src []byte) []byte {
    return s.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (s *CString) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(s.SizeBytes())
    s.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (s *CString) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (s *CString) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(s.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    s.UnmarshalBytes(buf)
    return length, err
}

func (s *CString) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *CString) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEAccessIn) SizeBytes() int {
    return 8
}

func (f *FUSEAccessIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mask))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEAccessIn) UnmarshalBytes(src []byte) []byte {
    f.Mask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEAccessIn) Packed() bool {
    return true
}

func (f *FUSEAccessIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEAccessIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEAccessIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEAccessIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEAccessIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEAccessIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEAccessIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (a *FUSEAttr) SizeBytes() int {
    return 88
}

func (a *FUSEAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Atime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Mtime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(a.Ctime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.AtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.MtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.CtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Nlink))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.Rdev))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(a.BlkSize))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (a *FUSEAttr) UnmarshalBytes(src []byte) []byte {
    a.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Atime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Mtime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.Ctime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    a.AtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.MtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.CtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Nlink = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.Rdev = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    a.BlkSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *FUSEAttr) Packed() bool {
    return true
}

func (a *FUSEAttr) MarshalUnsafe(dst []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(a), uintptr(size))
    return dst[size:]
}

func (a *FUSEAttr) UnmarshalUnsafe(src []byte) []byte {
    size := a.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(a), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (a *FUSEAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *FUSEAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

func (a *FUSEAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(a)
    return length, err
}

func (a *FUSEAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

func (a *FUSEAttr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(a)))
    hdr.Len = a.SizeBytes()
    hdr.Cap = a.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(a)
    return int64(length), err
}

func (f *FUSEAttrOut) SizeBytes() int {
    return 16 +
        (*FUSEAttr)(nil).SizeBytes()
}

func (f *FUSEAttrOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNsec))
    dst = dst[4:]
    dst = dst[4:]
    dst = f.Attr.MarshalUnsafe(dst)
    return dst
}

func (f *FUSEAttrOut) UnmarshalBytes(src []byte) []byte {
    f.AttrValid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValidNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    src = f.Attr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEAttrOut) Packed() bool {
    return f.Attr.Packed()
}

func (f *FUSEAttrOut) MarshalUnsafe(dst []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    return f.MarshalBytes(dst)
}

func (f *FUSEAttrOut) UnmarshalUnsafe(src []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return f.UnmarshalBytes(src)
}

func (f *FUSEAttrOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        f.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEAttrOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEAttrOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        f.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEAttrOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEAttrOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSECreateIn) Packed() bool {
    return false
}

func (r *FUSECreateIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSECreateIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSECreateIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSECreateIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSECreateIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSECreateIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSECreateIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSECreateMeta) SizeBytes() int {
    return 16
}

func (f *FUSECreateMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSECreateMeta) UnmarshalBytes(src []byte) []byte {
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSECreateMeta) Packed() bool {
    return true
}

func (f *FUSECreateMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSECreateMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSECreateMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSECreateMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSECreateMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSECreateMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSECreateMeta) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSECreateOut) SizeBytes() int {
    return 0 +
        (*FUSEEntryOut)(nil).SizeBytes() +
        (*FUSEOpenOut)(nil).SizeBytes()
}

func (f *FUSECreateOut) MarshalBytes(dst []byte) []byte {
    dst = f.FUSEEntryOut.MarshalUnsafe(dst)
    dst = f.FUSEOpenOut.MarshalUnsafe(dst)
    return dst
}

func (f *FUSECreateOut) UnmarshalBytes(src []byte) []byte {
    src = f.FUSEEntryOut.UnmarshalUnsafe(src)
    src = f.FUSEOpenOut.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSECreateOut) Packed() bool {
    return f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed()
}

func (f *FUSECreateOut) MarshalUnsafe(dst []byte) []byte {
    if f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    return f.MarshalBytes(dst)
}

func (f *FUSECreateOut) UnmarshalUnsafe(src []byte) []byte {
    if f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return f.UnmarshalBytes(src)
}

func (f *FUSECreateOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        f.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSECreateOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSECreateOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        f.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSECreateOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSECreateOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.FUSEEntryOut.Packed() && f.FUSEOpenOut.Packed() {
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEDirent) Packed() bool {
    return false
}

func (r *FUSEDirent) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEDirent) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEDirent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEDirent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEDirent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEDirent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEDirent) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEDirentMeta) SizeBytes() int {
    return 24
}

func (f *FUSEDirentMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Off))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.NameLen))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Type))
    dst = dst[4:]
    return dst
}

func (f *FUSEDirentMeta) UnmarshalBytes(src []byte) []byte {
    f.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Off = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.NameLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Type = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEDirentMeta) Packed() bool {
    return true
}

func (f *FUSEDirentMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEDirentMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEDirentMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEDirentMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEDirentMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEDirentMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEDirentMeta) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEDirents) Packed() bool {
    return false
}

func (r *FUSEDirents) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEDirents) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEDirents) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEDirents) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEDirents) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEDirents) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEDirents) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEEmptyIn) Packed() bool {
    return false
}

func (r *FUSEEmptyIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEEmptyIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEEmptyIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEEmptyIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEEmptyIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEEmptyIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEEmptyIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEEntryOut) SizeBytes() int {
    return 40 +
        (*FUSEAttr)(nil).SizeBytes()
}

func (f *FUSEEntryOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Generation))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.EntryValid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.AttrValid))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.EntryValidNSec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.AttrValidNSec))
    dst = dst[4:]
    dst = f.Attr.MarshalUnsafe(dst)
    return dst
}

func (f *FUSEEntryOut) UnmarshalBytes(src []byte) []byte {
    f.NodeID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Generation = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.EntryValid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AttrValid = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.EntryValidNSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.AttrValidNSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = f.Attr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEEntryOut) Packed() bool {
    return f.Attr.Packed()
}

func (f *FUSEEntryOut) MarshalUnsafe(dst []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    return f.MarshalBytes(dst)
}

func (f *FUSEEntryOut) UnmarshalUnsafe(src []byte) []byte {
    if f.Attr.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return f.UnmarshalBytes(src)
}

func (f *FUSEEntryOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        f.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEEntryOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEEntryOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Attr.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        f.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEEntryOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEEntryOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Attr.Packed() {
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEFallocateIn) SizeBytes() int {
    return 32
}

func (f *FUSEFallocateIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEFallocateIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEFallocateIn) Packed() bool {
    return true
}

func (f *FUSEFallocateIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEFallocateIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEFallocateIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEFallocateIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEFallocateIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEFallocateIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEFallocateIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEFlushIn) SizeBytes() int {
    return 24
}

func (f *FUSEFlushIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    return dst
}

func (f *FUSEFlushIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = src[4:]
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEFlushIn) Packed() bool {
    return true
}

func (f *FUSEFlushIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEFlushIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEFlushIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEFlushIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEFlushIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEFlushIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEFlushIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEFsyncIn) SizeBytes() int {
    return 16
}

func (f *FUSEFsyncIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.FsyncFlags))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEFsyncIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.FsyncFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEFsyncIn) Packed() bool {
    return true
}

func (f *FUSEFsyncIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEFsyncIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEFsyncIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEFsyncIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEFsyncIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEFsyncIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEFsyncIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEGetAttrIn) SizeBytes() int {
    return 16
}

func (f *FUSEGetAttrIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.GetAttrFlags))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    return dst
}

func (f *FUSEGetAttrIn) UnmarshalBytes(src []byte) []byte {
    f.GetAttrFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetAttrIn) Packed() bool {
    return true
}

func (f *FUSEGetAttrIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEGetAttrIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEGetAttrIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEGetAttrIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEGetAttrIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEGetAttrIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEGetAttrIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEGetXattrHdr) SizeBytes() int {
    return 8
}

func (f *FUSEGetXattrHdr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEGetXattrHdr) UnmarshalBytes(src []byte) []byte {
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetXattrHdr) Packed() bool {
    return true
}

func (f *FUSEGetXattrHdr) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEGetXattrHdr) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEGetXattrHdr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEGetXattrHdr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEGetXattrHdr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEGetXattrHdr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEGetXattrHdr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEGetXattrIn) Packed() bool {
    return false
}

func (r *FUSEGetXattrIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEGetXattrIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEGetXattrIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEGetXattrIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEGetXattrIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEGetXattrIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEGetXattrIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEGetXattrOut) SizeBytes() int {
    return 8
}

func (f *FUSEGetXattrOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEGetXattrOut) UnmarshalBytes(src []byte) []byte {
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEGetXattrOut) Packed() bool {
    return true
}

func (f *FUSEGetXattrOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEGetXattrOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEGetXattrOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEGetXattrOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEGetXattrOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEGetXattrOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEGetXattrOut) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEHeaderIn) SizeBytes() int {
    return 28 +
        (*FUSEOpcode)(nil).SizeBytes() +
        (*FUSEOpID)(nil).SizeBytes()
}

func (f *FUSEHeaderIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    dst = f.Opcode.MarshalUnsafe(dst)
    dst = f.Unique.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.NodeID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.PID))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEHeaderIn) UnmarshalBytes(src []byte) []byte {
    f.Len = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = f.Opcode.UnmarshalUnsafe(src)
    src = f.Unique.UnmarshalUnsafe(src)
    f.NodeID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.PID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderIn) Packed() bool {
    return f.Opcode.Packed() && f.Unique.Packed()
}

func (f *FUSEHeaderIn) MarshalUnsafe(dst []byte) []byte {
    if f.Opcode.Packed() && f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    return f.MarshalBytes(dst)
}

func (f *FUSEHeaderIn) UnmarshalUnsafe(src []byte) []byte {
    if f.Opcode.Packed() && f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return f.UnmarshalBytes(src)
}

func (f *FUSEHeaderIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        f.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEHeaderIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEHeaderIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        f.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEHeaderIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEHeaderIn) WriteTo(writer io.Writer) (int64, error) {
    if !f.Opcode.Packed() && f.Unique.Packed() {
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEHeaderOut) SizeBytes() int {
    return 8 +
        (*FUSEOpID)(nil).SizeBytes()
}

func (f *FUSEHeaderOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Len))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Error))
    dst = dst[4:]
    dst = f.Unique.MarshalUnsafe(dst)
    return dst
}

func (f *FUSEHeaderOut) UnmarshalBytes(src []byte) []byte {
    f.Len = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Error = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = f.Unique.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEHeaderOut) Packed() bool {
    return f.Unique.Packed()
}

func (f *FUSEHeaderOut) MarshalUnsafe(dst []byte) []byte {
    if f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
        return dst[size:]
    }
    return f.MarshalBytes(dst)
}

func (f *FUSEHeaderOut) UnmarshalUnsafe(src []byte) []byte {
    if f.Unique.Packed() {
        size := f.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return f.UnmarshalBytes(src)
}

func (f *FUSEHeaderOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Unique.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        f.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEHeaderOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEHeaderOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !f.Unique.Packed() {
        buf := cc.CopyScratchBuffer(f.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        f.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEHeaderOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEHeaderOut) WriteTo(writer io.Writer) (int64, error) {
    if !f.Unique.Packed() {
        buf := make([]byte, f.SizeBytes())
        f.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEInitIn) SizeBytes() int {
    return 16
}

func (f *FUSEInitIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    return dst
}

func (f *FUSEInitIn) UnmarshalBytes(src []byte) []byte {
    f.Major = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitIn) Packed() bool {
    return true
}

func (f *FUSEInitIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEInitIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEInitIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEInitIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEInitIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEInitIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEInitIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEInitOut) SizeBytes() int {
    return 32 +
        4*8
}

func (f *FUSEInitOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Major))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Minor))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MaxReadahead))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.MaxBackground))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.CongestionThreshold))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MaxWrite))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.TimeGran))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(f.MaxPages))
    dst = dst[2:]
    dst = dst[2:]
    dst = dst[4*(8):]
    return dst
}

func (f *FUSEInitOut) UnmarshalBytes(src []byte) []byte {
    f.Major = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Minor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxReadahead = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxBackground = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.CongestionThreshold = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    f.MaxWrite = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.TimeGran = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MaxPages = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[2:]
    src = src[4*(8):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEInitOut) Packed() bool {
    return true
}

func (f *FUSEInitOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEInitOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEInitOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEInitOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEInitOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEInitOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEInitOut) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSELinkIn) Packed() bool {
    return false
}

func (r *FUSELinkIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSELinkIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSELinkIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSELinkIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSELinkIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSELinkIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSELinkIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSELookupIn) Packed() bool {
    return false
}

func (r *FUSELookupIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSELookupIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSELookupIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSELookupIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSELookupIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSELookupIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSELookupIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEMkdirIn) Packed() bool {
    return false
}

func (r *FUSEMkdirIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEMkdirIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEMkdirIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEMkdirIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEMkdirIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEMkdirIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEMkdirIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEMkdirMeta) SizeBytes() int {
    return 8
}

func (f *FUSEMkdirMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    return dst
}

func (f *FUSEMkdirMeta) UnmarshalBytes(src []byte) []byte {
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEMkdirMeta) Packed() bool {
    return true
}

func (f *FUSEMkdirMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEMkdirMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEMkdirMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEMkdirMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEMkdirMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEMkdirMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEMkdirMeta) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEMknodIn) Packed() bool {
    return false
}

func (r *FUSEMknodIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEMknodIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEMknodIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEMknodIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEMknodIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEMknodIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEMknodIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEMknodMeta) SizeBytes() int {
    return 16
}

func (f *FUSEMknodMeta) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Rdev))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Umask))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEMknodMeta) UnmarshalBytes(src []byte) []byte {
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Rdev = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Umask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEMknodMeta) Packed() bool {
    return true
}

func (f *FUSEMknodMeta) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEMknodMeta) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEMknodMeta) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEMknodMeta) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEMknodMeta) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEMknodMeta) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEMknodMeta) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FUSEOpID) SizeBytes() int {
    return 8
}

func (f *FUSEOpID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*f))
    return dst[8:]
}

func (f *FUSEOpID) UnmarshalBytes(src []byte) []byte {
    *f = FUSEOpID(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpID) Packed() bool {
    return true
}

func (f *FUSEOpID) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEOpID) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEOpID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpID) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (f *FUSEOpcode) SizeBytes() int {
    return 4
}

func (f *FUSEOpcode) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*f))
    return dst[4:]
}

func (f *FUSEOpcode) UnmarshalBytes(src []byte) []byte {
    *f = FUSEOpcode(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpcode) Packed() bool {
    return true
}

func (f *FUSEOpcode) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEOpcode) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEOpcode) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpcode) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpcode) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpcode) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpcode) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEOpenIn) SizeBytes() int {
    return 8
}

func (f *FUSEOpenIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEOpenIn) UnmarshalBytes(src []byte) []byte {
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpenIn) Packed() bool {
    return true
}

func (f *FUSEOpenIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEOpenIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEOpenIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpenIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpenIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpenIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpenIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEOpenOut) SizeBytes() int {
    return 16
}

func (f *FUSEOpenOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.OpenFlag))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEOpenOut) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.OpenFlag = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEOpenOut) Packed() bool {
    return true
}

func (f *FUSEOpenOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEOpenOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEOpenOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpenOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpenOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEOpenOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEOpenOut) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEReadIn) SizeBytes() int {
    return 40
}

func (f *FUSEReadIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.ReadFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEReadIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ReadFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEReadIn) Packed() bool {
    return true
}

func (f *FUSEReadIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEReadIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEReadIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEReadIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEReadIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEReadIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEReadIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEReleaseIn) SizeBytes() int {
    return 24
}

func (f *FUSEReleaseIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.ReleaseFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    return dst
}

func (f *FUSEReleaseIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.ReleaseFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEReleaseIn) Packed() bool {
    return true
}

func (f *FUSEReleaseIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEReleaseIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEReleaseIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEReleaseIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEReleaseIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEReleaseIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEReleaseIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSERenameIn) Packed() bool {
    return false
}

func (r *FUSERenameIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSERenameIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSERenameIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSERenameIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSERenameIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSERenameIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSERenameIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSERmDirIn) Packed() bool {
    return false
}

func (r *FUSERmDirIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSERmDirIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSERmDirIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSERmDirIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSERmDirIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSERmDirIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSERmDirIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSESetAttrIn) SizeBytes() int {
    return 88
}

func (f *FUSESetAttrIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Valid))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Atime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Mtime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Ctime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.AtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.MtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.CtimeNsec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Mode))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.GID))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSESetAttrIn) UnmarshalBytes(src []byte) []byte {
    f.Valid = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Atime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Mtime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Ctime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.AtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.MtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.CtimeNsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    f.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSESetAttrIn) Packed() bool {
    return true
}

func (f *FUSESetAttrIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSESetAttrIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSESetAttrIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSESetAttrIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSESetAttrIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSESetAttrIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSESetAttrIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSESetXattrHdr) SizeBytes() int {
    return 8
}

func (f *FUSESetXattrHdr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    return dst
}

func (f *FUSESetXattrHdr) UnmarshalBytes(src []byte) []byte {
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSESetXattrHdr) Packed() bool {
    return true
}

func (f *FUSESetXattrHdr) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSESetXattrHdr) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSESetXattrHdr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSESetXattrHdr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSESetXattrHdr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSESetXattrHdr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSESetXattrHdr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSESetXattrIn) Packed() bool {
    return false
}

func (r *FUSESetXattrIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSESetXattrIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSESetXattrIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSESetXattrIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSESetXattrIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSESetXattrIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSESetXattrIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEStatfsOut) SizeBytes() int {
    return 56 +
        4*6
}

func (f *FUSEStatfsOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Blocks))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.BlocksFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.BlocksAvailable))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Files))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.FilesFree))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.BlockSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.NameLength))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.FragmentSize))
    dst = dst[4:]
    dst = dst[4:]
    for idx := 0; idx < 6; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Spare[idx]))
        dst = dst[4:]
    }
    return dst
}

func (f *FUSEStatfsOut) UnmarshalBytes(src []byte) []byte {
    f.Blocks = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.BlocksFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.BlocksAvailable = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Files = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.FilesFree = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.BlockSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.NameLength = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.FragmentSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    for idx := 0; idx < 6; idx++ {
        f.Spare[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEStatfsOut) Packed() bool {
    return true
}

func (f *FUSEStatfsOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEStatfsOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEStatfsOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEStatfsOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEStatfsOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEStatfsOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEStatfsOut) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSESymlinkIn) Packed() bool {
    return false
}

func (r *FUSESymlinkIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSESymlinkIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSESymlinkIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSESymlinkIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSESymlinkIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSESymlinkIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSESymlinkIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEUnlinkIn) Packed() bool {
    return false
}

func (r *FUSEUnlinkIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEUnlinkIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEUnlinkIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEUnlinkIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEUnlinkIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEUnlinkIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEUnlinkIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (f *FUSEWriteIn) SizeBytes() int {
    return 40
}

func (f *FUSEWriteIn) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Fh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.Offset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.WriteFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(f.LockOwner))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Flags))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEWriteIn) UnmarshalBytes(src []byte) []byte {
    f.Fh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.WriteFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    f.LockOwner = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    f.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteIn) Packed() bool {
    return true
}

func (f *FUSEWriteIn) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEWriteIn) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEWriteIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEWriteIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEWriteIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEWriteIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEWriteIn) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

func (f *FUSEWriteOut) SizeBytes() int {
    return 8
}

func (f *FUSEWriteOut) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(f.Size))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (f *FUSEWriteOut) UnmarshalBytes(src []byte) []byte {
    f.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (f *FUSEWriteOut) Packed() bool {
    return true
}

func (f *FUSEWriteOut) MarshalUnsafe(dst []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(f), uintptr(size))
    return dst[size:]
}

func (f *FUSEWriteOut) UnmarshalUnsafe(src []byte) []byte {
    size := f.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(f), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (f *FUSEWriteOut) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEWriteOut) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyOutN(cc, addr, f.SizeBytes())
}

func (f *FUSEWriteOut) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(f)
    return length, err
}

func (f *FUSEWriteOut) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return f.CopyInN(cc, addr, f.SizeBytes())
}

func (f *FUSEWriteOut) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(f)))
    hdr.Len = f.SizeBytes()
    hdr.Cap = f.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(f)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *FUSEWritePayloadIn) Packed() bool {
    return false
}

func (r *FUSEWritePayloadIn) MarshalUnsafe(dst []byte) []byte {
    return r.MarshalBytes(dst)
}

func (r *FUSEWritePayloadIn) UnmarshalUnsafe(src []byte) []byte {
    return r.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (r *FUSEWritePayloadIn) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    r.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (r *FUSEWritePayloadIn) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (r *FUSEWritePayloadIn) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(r.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    r.UnmarshalBytes(buf)
    return length, err
}

func (r *FUSEWritePayloadIn) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *FUSEWritePayloadIn) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, r.SizeBytes())
    r.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (r *RobustListHead) SizeBytes() int {
    return 24
}

func (r *RobustListHead) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.List))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.FutexOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.ListOpPending))
    dst = dst[8:]
    return dst
}

func (r *RobustListHead) UnmarshalBytes(src []byte) []byte {
    r.List = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.FutexOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ListOpPending = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RobustListHead) Packed() bool {
    return true
}

func (r *RobustListHead) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

func (r *RobustListHead) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (r *RobustListHead) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RobustListHead) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RobustListHead) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RobustListHead) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RobustListHead) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (i *IOCqRingOffsets) SizeBytes() int {
    return 40
}

func (i *IOCqRingOffsets) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Head))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Tail))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Overflow))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Cqes))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Resv1))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Resv2))
    dst = dst[8:]
    return dst
}

func (i *IOCqRingOffsets) UnmarshalBytes(src []byte) []byte {
    i.Head = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Tail = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Overflow = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Cqes = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv1 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOCqRingOffsets) Packed() bool {
    return true
}

func (i *IOCqRingOffsets) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOCqRingOffsets) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOCqRingOffsets) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOCqRingOffsets) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOCqRingOffsets) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOCqRingOffsets) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOCqRingOffsets) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *IORingIndex) SizeBytes() int {
    return 4
}

func (i *IORingIndex) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*i))
    return dst[4:]
}

func (i *IORingIndex) UnmarshalBytes(src []byte) []byte {
    *i = IORingIndex(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IORingIndex) Packed() bool {
    return true
}

func (i *IORingIndex) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IORingIndex) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IORingIndex) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IORingIndex) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IORingIndex) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IORingIndex) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IORingIndex) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IORings) SizeBytes() int {
    return 32 +
        (*IOUring)(nil).SizeBytes() +
        (*IOUring)(nil).SizeBytes() +
        1*32
}

func (i *IORings) MarshalBytes(dst []byte) []byte {
    dst = i.Sq.MarshalUnsafe(dst)
    dst = i.Cq.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqRingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqRingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqRingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqRingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.sqDropped))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.sqFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.cqFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqOverflow))
    dst = dst[4:]
    dst = dst[1*(32):]
    return dst
}

func (i *IORings) UnmarshalBytes(src []byte) []byte {
    src = i.Sq.UnmarshalUnsafe(src)
    src = i.Cq.UnmarshalUnsafe(src)
    i.SqRingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqRingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SqRingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqRingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.sqDropped = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.sqFlags = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.cqFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqOverflow = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(32):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IORings) Packed() bool {
    return i.Cq.Packed() && i.Sq.Packed()
}

func (i *IORings) MarshalUnsafe(dst []byte) []byte {
    if i.Cq.Packed() && i.Sq.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IORings) UnmarshalUnsafe(src []byte) []byte {
    if i.Cq.Packed() && i.Sq.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IORings) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Cq.Packed() && i.Sq.Packed() {
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

func (i *IORings) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IORings) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Cq.Packed() && i.Sq.Packed() {
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

func (i *IORings) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IORings) WriteTo(writer io.Writer) (int64, error) {
    if !i.Cq.Packed() && i.Sq.Packed() {
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

func (i *IOSqRingOffsets) SizeBytes() int {
    return 40
}

func (i *IOSqRingOffsets) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Head))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Tail))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingMask))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.RingEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Dropped))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Array))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Resv1))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Resv2))
    dst = dst[8:]
    return dst
}

func (i *IOSqRingOffsets) UnmarshalBytes(src []byte) []byte {
    i.Head = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Tail = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingMask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.RingEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Dropped = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Array = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv1 = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Resv2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOSqRingOffsets) Packed() bool {
    return true
}

func (i *IOSqRingOffsets) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOSqRingOffsets) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOSqRingOffsets) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOSqRingOffsets) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOSqRingOffsets) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOSqRingOffsets) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOSqRingOffsets) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IOUring) SizeBytes() int {
    return 8 +
        1*60 +
        1*60
}

func (i *IOUring) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Head))
    dst = dst[4:]
    dst = dst[1*(60):]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Tail))
    dst = dst[4:]
    dst = dst[1*(60):]
    return dst
}

func (i *IOUring) UnmarshalBytes(src []byte) []byte {
    i.Head = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(60):]
    i.Tail = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(60):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUring) Packed() bool {
    return true
}

func (i *IOUring) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOUring) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOUring) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOUring) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOUring) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOUring) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOUring) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IOUringCqe) SizeBytes() int {
    return 16
}

func (i *IOUringCqe) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.UserData))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Res))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    return dst
}

func (i *IOUringCqe) UnmarshalBytes(src []byte) []byte {
    i.UserData = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Res = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUringCqe) Packed() bool {
    return true
}

func (i *IOUringCqe) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOUringCqe) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOUringCqe) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOUringCqe) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOUringCqe) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOUringCqe) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOUringCqe) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IOUringParams) SizeBytes() int {
    return 28 +
        4*3 +
        (*IOSqRingOffsets)(nil).SizeBytes() +
        (*IOCqRingOffsets)(nil).SizeBytes()
}

func (i *IOUringParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CqEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqThreadCPU))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SqThreadIdle))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Features))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.WqFd))
    dst = dst[4:]
    for idx := 0; idx < 3; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Resv[idx]))
        dst = dst[4:]
    }
    dst = i.SqOff.MarshalUnsafe(dst)
    dst = i.CqOff.MarshalUnsafe(dst)
    return dst
}

func (i *IOUringParams) UnmarshalBytes(src []byte) []byte {
    i.SqEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CqEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SqThreadCPU = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SqThreadIdle = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Features = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.WqFd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 3; idx++ {
        i.Resv[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    src = i.SqOff.UnmarshalUnsafe(src)
    src = i.CqOff.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUringParams) Packed() bool {
    return i.CqOff.Packed() && i.SqOff.Packed()
}

func (i *IOUringParams) MarshalUnsafe(dst []byte) []byte {
    if i.CqOff.Packed() && i.SqOff.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IOUringParams) UnmarshalUnsafe(src []byte) []byte {
    if i.CqOff.Packed() && i.SqOff.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IOUringParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.CqOff.Packed() && i.SqOff.Packed() {
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

func (i *IOUringParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOUringParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.CqOff.Packed() && i.SqOff.Packed() {
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

func (i *IOUringParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOUringParams) WriteTo(writer io.Writer) (int64, error) {
    if !i.CqOff.Packed() && i.SqOff.Packed() {
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

func (i *IOUringSqe) SizeBytes() int {
    return 64
}

func (i *IOUringSqe) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Opcode)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.IoPrio))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Fd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.OffOrAddrOrCmdOp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.AddrOrSpliceOff))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Len))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.specialFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.UserData))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.BufIndexOrGroup))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.personality))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.spliceFDOrFileIndex))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.addr3))
    dst = dst[8:]
    dst = dst[8:]
    return dst
}

func (i *IOUringSqe) UnmarshalBytes(src []byte) []byte {
    i.Opcode = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.IoPrio = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Fd = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.OffOrAddrOrCmdOp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.AddrOrSpliceOff = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.Len = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.specialFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UserData = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.BufIndexOrGroup = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.personality = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.spliceFDOrFileIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.addr3 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IOUringSqe) Packed() bool {
    return true
}

func (i *IOUringSqe) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IOUringSqe) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IOUringSqe) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOUringSqe) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IOUringSqe) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IOUringSqe) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IOUringSqe) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IPCPerm) SizeBytes() int {
    return 48
}

func (i *IPCPerm) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Key))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CUID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.CGID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Mode))
    dst = dst[2:]
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Seq))
    dst = dst[2:]
    dst = dst[2:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.unused1))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.unused2))
    dst = dst[8:]
    return dst
}

func (i *IPCPerm) UnmarshalBytes(src []byte) []byte {
    i.Key = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CUID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.CGID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Mode = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[2:]
    i.Seq = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[2:]
    src = src[4:]
    i.unused1 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    i.unused2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPCPerm) Packed() bool {
    return true
}

func (i *IPCPerm) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IPCPerm) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IPCPerm) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IPCPerm) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPCPerm) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IPCPerm) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPCPerm) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (s *Sysinfo) SizeBytes() int {
    return 78 +
        8*3 +
        1*6
}

func (s *Sysinfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Uptime))
    dst = dst[8:]
    for idx := 0; idx < 3; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Loads[idx]))
        dst = dst[8:]
    }
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.TotalRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FreeRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SharedRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.BufferRAM))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.TotalSwap))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FreeSwap))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Procs))
    dst = dst[2:]
    dst = dst[1*(6):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.TotalHigh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.FreeHigh))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Unit))
    dst = dst[4:]
    return dst
}

func (s *Sysinfo) UnmarshalBytes(src []byte) []byte {
    s.Uptime = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 3; idx++ {
        s.Loads[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    s.TotalRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SharedRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.BufferRAM = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.TotalSwap = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeSwap = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Procs = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(6):]
    s.TotalHigh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.FreeHigh = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unit = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sysinfo) Packed() bool {
    return false
}

func (s *Sysinfo) MarshalUnsafe(dst []byte) []byte {
    return s.MarshalBytes(dst)
}

func (s *Sysinfo) UnmarshalUnsafe(src []byte) []byte {
    return s.UnmarshalBytes(src)
}

func (s *Sysinfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(s.SizeBytes())
    s.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (s *Sysinfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *Sysinfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(s.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf[:limit])
    s.UnmarshalBytes(buf)
    return length, err
}

func (s *Sysinfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *Sysinfo) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (n *NumaPolicy) SizeBytes() int {
    return 4
}

func (n *NumaPolicy) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*n))
    return dst[4:]
}

func (n *NumaPolicy) UnmarshalBytes(src []byte) []byte {
    *n = NumaPolicy(int32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NumaPolicy) Packed() bool {
    return true
}

func (n *NumaPolicy) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NumaPolicy) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NumaPolicy) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NumaPolicy) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NumaPolicy) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NumaPolicy) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NumaPolicy) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (m *MqAttr) SizeBytes() int {
    return 32 +
        8*4
}

func (m *MqAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqFlags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqMaxmsg))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqMsgsize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MqCurmsgs))
    dst = dst[8:]
    dst = dst[8*(4):]
    return dst
}

func (m *MqAttr) UnmarshalBytes(src []byte) []byte {
    m.MqFlags = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MqMaxmsg = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MqMsgsize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MqCurmsgs = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = src[8*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MqAttr) Packed() bool {
    return true
}

func (m *MqAttr) MarshalUnsafe(dst []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
    return dst[size:]
}

func (m *MqAttr) UnmarshalUnsafe(src []byte) []byte {
    size := m.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (m *MqAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(m)
    return length, err
}

func (m *MqAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

func (m *MqAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(m)
    return length, err
}

func (m *MqAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

func (m *MqAttr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(m)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (b *MsgBuf) Packed() bool {
    return false
}

func (b *MsgBuf) MarshalUnsafe(dst []byte) []byte {
    return b.MarshalBytes(dst)
}

func (b *MsgBuf) UnmarshalUnsafe(src []byte) []byte {
    return b.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (b *MsgBuf) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(b.SizeBytes())
    b.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (b *MsgBuf) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyOutN(cc, addr, b.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (b *MsgBuf) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(b.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    b.UnmarshalBytes(buf)
    return length, err
}

func (b *MsgBuf) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return b.CopyInN(cc, addr, b.SizeBytes())
}

func (b *MsgBuf) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, b.SizeBytes())
    b.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (m *MsgInfo) SizeBytes() int {
    return 30
}

func (m *MsgInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgPool))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMap))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMax))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMnb))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgMni))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgSsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgTql))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(m.MsgSeg))
    dst = dst[2:]
    return dst
}

func (m *MsgInfo) UnmarshalBytes(src []byte) []byte {
    m.MsgPool = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMap = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMax = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMnb = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgMni = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgSsz = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgTql = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgSeg = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsgInfo) Packed() bool {
    return false
}

func (m *MsgInfo) MarshalUnsafe(dst []byte) []byte {
    return m.MarshalBytes(dst)
}

func (m *MsgInfo) UnmarshalUnsafe(src []byte) []byte {
    return m.UnmarshalBytes(src)
}

func (m *MsgInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(m.SizeBytes())
    m.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (m *MsgInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

func (m *MsgInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(m.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf[:limit])
    m.UnmarshalBytes(buf)
    return length, err
}

func (m *MsgInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

func (m *MsgInfo) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, m.SizeBytes())
    m.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (m *MsqidDS) SizeBytes() int {
    return 48 +
        (*IPCPerm)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes()
}

func (m *MsqidDS) MarshalBytes(dst []byte) []byte {
    dst = m.MsgPerm.MarshalUnsafe(dst)
    dst = m.MsgStime.MarshalUnsafe(dst)
    dst = m.MsgRtime.MarshalUnsafe(dst)
    dst = m.MsgCtime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MsgCbytes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MsgQnum))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.MsgQbytes))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgLspid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(m.MsgLrpid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.unused4))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(m.unused5))
    dst = dst[8:]
    return dst
}

func (m *MsqidDS) UnmarshalBytes(src []byte) []byte {
    src = m.MsgPerm.UnmarshalUnsafe(src)
    src = m.MsgStime.UnmarshalUnsafe(src)
    src = m.MsgRtime.UnmarshalUnsafe(src)
    src = m.MsgCtime.UnmarshalUnsafe(src)
    m.MsgCbytes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MsgQnum = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MsgQbytes = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.MsgLspid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.MsgLrpid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    m.unused4 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    m.unused5 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (m *MsqidDS) Packed() bool {
    return m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed()
}

func (m *MsqidDS) MarshalUnsafe(dst []byte) []byte {
    if m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(m), uintptr(size))
        return dst[size:]
    }
    return m.MarshalBytes(dst)
}

func (m *MsqidDS) UnmarshalUnsafe(src []byte) []byte {
    if m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        size := m.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(m), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return m.UnmarshalBytes(src)
}

func (m *MsqidDS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        buf := cc.CopyScratchBuffer(m.SizeBytes())
        m.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(m)
    return length, err
}

func (m *MsqidDS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyOutN(cc, addr, m.SizeBytes())
}

func (m *MsqidDS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        buf := cc.CopyScratchBuffer(m.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        m.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(m)
    return length, err
}

func (m *MsqidDS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return m.CopyInN(cc, addr, m.SizeBytes())
}

func (m *MsqidDS) WriteTo(writer io.Writer) (int64, error) {
    if !m.MsgCtime.Packed() && m.MsgPerm.Packed() && m.MsgRtime.Packed() && m.MsgStime.Packed() {
        buf := make([]byte, m.SizeBytes())
        m.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(m)))
    hdr.Len = m.SizeBytes()
    hdr.Cap = m.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(m)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (e *EthtoolCmd) SizeBytes() int {
    return 4
}

func (e *EthtoolCmd) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*e))
    return dst[4:]
}

func (e *EthtoolCmd) UnmarshalBytes(src []byte) []byte {
    *e = EthtoolCmd(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EthtoolCmd) Packed() bool {
    return true
}

func (e *EthtoolCmd) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *EthtoolCmd) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *EthtoolCmd) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EthtoolCmd) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *EthtoolCmd) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EthtoolCmd) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *EthtoolCmd) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func (e *EthtoolGFeatures) SizeBytes() int {
    return 8
}

func (e *EthtoolGFeatures) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Cmd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Size))
    dst = dst[4:]
    return dst
}

func (e *EthtoolGFeatures) UnmarshalBytes(src []byte) []byte {
    e.Cmd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EthtoolGFeatures) Packed() bool {
    return true
}

func (e *EthtoolGFeatures) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *EthtoolGFeatures) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *EthtoolGFeatures) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EthtoolGFeatures) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *EthtoolGFeatures) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EthtoolGFeatures) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *EthtoolGFeatures) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func (e *EthtoolGetFeaturesBlock) SizeBytes() int {
    return 16
}

func (e *EthtoolGetFeaturesBlock) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Available))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Requested))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Active))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.NeverChanged))
    dst = dst[4:]
    return dst
}

func (e *EthtoolGetFeaturesBlock) UnmarshalBytes(src []byte) []byte {
    e.Available = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Requested = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.Active = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    e.NeverChanged = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EthtoolGetFeaturesBlock) Packed() bool {
    return true
}

func (e *EthtoolGetFeaturesBlock) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *EthtoolGetFeaturesBlock) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *EthtoolGetFeaturesBlock) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EthtoolGetFeaturesBlock) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *EthtoolGetFeaturesBlock) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EthtoolGetFeaturesBlock) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *EthtoolGetFeaturesBlock) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func (i *IFConf) SizeBytes() int {
    return 12 +
        1*4
}

func (i *IFConf) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Len))
    dst = dst[4:]
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Ptr))
    dst = dst[8:]
    return dst
}

func (i *IFConf) UnmarshalBytes(src []byte) []byte {
    i.Len = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    i.Ptr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IFConf) Packed() bool {
    return true
}

func (i *IFConf) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IFConf) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IFConf) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IFConf) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IFConf) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IFConf) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IFConf) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (ifr *IFReq) SizeBytes() int {
    return 0 +
        1*IFNAMSIZ +
        1*24
}

func (ifr *IFReq) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(ifr.IFName[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 24; idx++ {
        dst[0] = byte(ifr.Data[idx])
        dst = dst[1:]
    }
    return dst
}

func (ifr *IFReq) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < IFNAMSIZ; idx++ {
        ifr.IFName[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 24; idx++ {
        ifr.Data[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ifr *IFReq) Packed() bool {
    return true
}

func (ifr *IFReq) MarshalUnsafe(dst []byte) []byte {
    size := ifr.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(ifr), uintptr(size))
    return dst[size:]
}

func (ifr *IFReq) UnmarshalUnsafe(src []byte) []byte {
    size := ifr.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(ifr), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (ifr *IFReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ifr)))
    hdr.Len = ifr.SizeBytes()
    hdr.Cap = ifr.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(ifr)
    return length, err
}

func (ifr *IFReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ifr.CopyOutN(cc, addr, ifr.SizeBytes())
}

func (ifr *IFReq) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ifr)))
    hdr.Len = ifr.SizeBytes()
    hdr.Cap = ifr.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(ifr)
    return length, err
}

func (ifr *IFReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ifr.CopyInN(cc, addr, ifr.SizeBytes())
}

func (ifr *IFReq) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ifr)))
    hdr.Len = ifr.SizeBytes()
    hdr.Cap = ifr.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(ifr)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (en *ErrorName) SizeBytes() int {
    return 1 * XT_FUNCTION_MAXNAMELEN
}

func (en *ErrorName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < XT_FUNCTION_MAXNAMELEN; idx++ {
        dst[0] = byte(en[idx])
        dst = dst[1:]
    }
    return dst
}

func (en *ErrorName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < XT_FUNCTION_MAXNAMELEN; idx++ {
        en[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (en *ErrorName) Packed() bool {
    return true
}

func (en *ErrorName) MarshalUnsafe(dst []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&en[0]), uintptr(size))
    return dst[size:]
}

func (en *ErrorName) UnmarshalUnsafe(src []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(en), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (en *ErrorName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(en)
    return length, err
}

func (en *ErrorName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyOutN(cc, addr, en.SizeBytes())
}

func (en *ErrorName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(en)
    return length, err
}

func (en *ErrorName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyInN(cc, addr, en.SizeBytes())
}

func (en *ErrorName) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(en)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (en *ExtensionName) SizeBytes() int {
    return 1 * XT_EXTENSION_MAXNAMELEN
}

func (en *ExtensionName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < XT_EXTENSION_MAXNAMELEN; idx++ {
        dst[0] = byte(en[idx])
        dst = dst[1:]
    }
    return dst
}

func (en *ExtensionName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < XT_EXTENSION_MAXNAMELEN; idx++ {
        en[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (en *ExtensionName) Packed() bool {
    return true
}

func (en *ExtensionName) MarshalUnsafe(dst []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&en[0]), uintptr(size))
    return dst[size:]
}

func (en *ExtensionName) UnmarshalUnsafe(src []byte) []byte {
    size := en.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(en), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (en *ExtensionName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(en)
    return length, err
}

func (en *ExtensionName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyOutN(cc, addr, en.SizeBytes())
}

func (en *ExtensionName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(en)
    return length, err
}

func (en *ExtensionName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return en.CopyInN(cc, addr, en.SizeBytes())
}

func (en *ExtensionName) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(en)))
    hdr.Len = en.SizeBytes()
    hdr.Cap = en.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(en)
    return int64(length), err
}

func (i *IP6TRejectInfo) SizeBytes() int {
    return 4
}

func (i *IP6TRejectInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.With))
    dst = dst[4:]
    return dst
}

func (i *IP6TRejectInfo) UnmarshalBytes(src []byte) []byte {
    i.With = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TRejectInfo) Packed() bool {
    return true
}

func (i *IP6TRejectInfo) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IP6TRejectInfo) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IP6TRejectInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IP6TRejectInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IP6TRejectInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IP6TRejectInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IP6TRejectInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IPTEntry) SizeBytes() int {
    return 12 +
        (*IPTIP)(nil).SizeBytes() +
        (*XTCounters)(nil).SizeBytes()
}

func (i *IPTEntry) MarshalBytes(dst []byte) []byte {
    dst = i.IP.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    dst = i.Counters.MarshalUnsafe(dst)
    return dst
}

func (i *IPTEntry) UnmarshalBytes(src []byte) []byte {
    src = i.IP.UnmarshalUnsafe(src)
    i.NFCache = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = i.Counters.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTEntry) Packed() bool {
    return i.Counters.Packed() && i.IP.Packed()
}

func (i *IPTEntry) MarshalUnsafe(dst []byte) []byte {
    if i.Counters.Packed() && i.IP.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IPTEntry) UnmarshalUnsafe(src []byte) []byte {
    if i.Counters.Packed() && i.IP.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IPTEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
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

func (i *IPTEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
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

func (i *IPTEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.Counters.Packed() && i.IP.Packed() {
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

func (i *IPTGetEntries) SizeBytes() int {
    return 4 +
        (*TableName)(nil).SizeBytes() +
        1*4
}

func (i *IPTGetEntries) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    dst = dst[1*(4):]
    return dst
}

func (i *IPTGetEntries) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetEntries) Packed() bool {
    return i.Name.Packed()
}

func (i *IPTGetEntries) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IPTGetEntries) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IPTGetEntries) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IPTGetEntries) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTGetEntries) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IPTGetEntries) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTGetEntries) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
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

func (i *IPTGetinfo) SizeBytes() int {
    return 12 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

func (i *IPTGetinfo) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    return dst
}

func (i *IPTGetinfo) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.ValidHooks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTGetinfo) Packed() bool {
    return i.Name.Packed()
}

func (i *IPTGetinfo) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IPTGetinfo) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IPTGetinfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IPTGetinfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTGetinfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IPTGetinfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTGetinfo) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
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

func (i *IPTIP) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ
}

func (i *IPTIP) MarshalBytes(dst []byte) []byte {
    dst = i.Src.MarshalUnsafe(dst)
    dst = i.Dst.MarshalUnsafe(dst)
    dst = i.SrcMask.MarshalUnsafe(dst)
    dst = i.DstMask.MarshalUnsafe(dst)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
    return dst
}

func (i *IPTIP) UnmarshalBytes(src []byte) []byte {
    src = i.Src.UnmarshalUnsafe(src)
    src = i.Dst.UnmarshalUnsafe(src)
    src = i.SrcMask.UnmarshalUnsafe(src)
    src = i.DstMask.UnmarshalUnsafe(src)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTIP) Packed() bool {
    return i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed()
}

func (i *IPTIP) MarshalUnsafe(dst []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IPTIP) UnmarshalUnsafe(src []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IPTIP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
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

func (i *IPTIP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTIP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
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

func (i *IPTIP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
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

func (i *IPTOwnerInfo) SizeBytes() int {
    return 18 +
        1*16
}

func (i *IPTOwnerInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.GID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.PID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.SID))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i.Comm[idx])
        dst = dst[1:]
    }
    dst[0] = byte(i.Match)
    dst = dst[1:]
    dst[0] = byte(i.Invert)
    dst = dst[1:]
    return dst
}

func (i *IPTOwnerInfo) UnmarshalBytes(src []byte) []byte {
    i.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.PID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.SID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        i.Comm[idx] = src[0]
        src = src[1:]
    }
    i.Match = uint8(src[0])
    src = src[1:]
    i.Invert = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTOwnerInfo) Packed() bool {
    return false
}

func (i *IPTOwnerInfo) MarshalUnsafe(dst []byte) []byte {
    return i.MarshalBytes(dst)
}

func (i *IPTOwnerInfo) UnmarshalUnsafe(src []byte) []byte {
    return i.UnmarshalBytes(src)
}

func (i *IPTOwnerInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(i.SizeBytes())
    i.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (i *IPTOwnerInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTOwnerInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(i.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf[:limit])
    i.UnmarshalBytes(buf)
    return length, err
}

func (i *IPTOwnerInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTOwnerInfo) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, i.SizeBytes())
    i.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (i *IPTRejectInfo) SizeBytes() int {
    return 4
}

func (i *IPTRejectInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.With))
    dst = dst[4:]
    return dst
}

func (i *IPTRejectInfo) UnmarshalBytes(src []byte) []byte {
    i.With = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTRejectInfo) Packed() bool {
    return true
}

func (i *IPTRejectInfo) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *IPTRejectInfo) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *IPTRejectInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IPTRejectInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTRejectInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *IPTRejectInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTRejectInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *IPTReplace) SizeBytes() int {
    return 24 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

func (i *IPTReplace) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumCounters))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Counters))
    dst = dst[8:]
    return dst
}

func (i *IPTReplace) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.ValidHooks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.NumEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumCounters = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IPTReplace) Packed() bool {
    return i.Name.Packed()
}

func (i *IPTReplace) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IPTReplace) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IPTReplace) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IPTReplace) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IPTReplace) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IPTReplace) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IPTReplace) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIPTEntry) Packed() bool {
    return false
}

func (ke *KernelIPTEntry) MarshalUnsafe(dst []byte) []byte {
    return ke.MarshalBytes(dst)
}

func (ke *KernelIPTEntry) UnmarshalUnsafe(src []byte) []byte {
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIPTEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    ke.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (ke *KernelIPTEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIPTEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    ke.UnmarshalBytes(buf)
    return length, err
}

func (ke *KernelIPTEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

func (ke *KernelIPTEntry) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIPTGetEntries) Packed() bool {
    return false
}

func (ke *KernelIPTGetEntries) MarshalUnsafe(dst []byte) []byte {
    return ke.MarshalBytes(dst)
}

func (ke *KernelIPTGetEntries) UnmarshalUnsafe(src []byte) []byte {
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIPTGetEntries) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    ke.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (ke *KernelIPTGetEntries) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIPTGetEntries) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    ke.UnmarshalBytes(buf)
    return length, err
}

func (ke *KernelIPTGetEntries) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

func (ke *KernelIPTGetEntries) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (n *NfNATIPV4MultiRangeCompat) SizeBytes() int {
    return 4 +
        (*NfNATIPV4Range)(nil).SizeBytes()
}

func (n *NfNATIPV4MultiRangeCompat) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.RangeSize))
    dst = dst[4:]
    dst = n.RangeIPV4.MarshalUnsafe(dst)
    return dst
}

func (n *NfNATIPV4MultiRangeCompat) UnmarshalBytes(src []byte) []byte {
    n.RangeSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.RangeIPV4.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NfNATIPV4MultiRangeCompat) Packed() bool {
    return n.RangeIPV4.Packed()
}

func (n *NfNATIPV4MultiRangeCompat) MarshalUnsafe(dst []byte) []byte {
    if n.RangeIPV4.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NfNATIPV4MultiRangeCompat) UnmarshalUnsafe(src []byte) []byte {
    if n.RangeIPV4.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NfNATIPV4MultiRangeCompat) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.RangeIPV4.Packed() {
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

func (n *NfNATIPV4MultiRangeCompat) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NfNATIPV4MultiRangeCompat) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.RangeIPV4.Packed() {
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

func (n *NfNATIPV4MultiRangeCompat) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NfNATIPV4MultiRangeCompat) WriteTo(writer io.Writer) (int64, error) {
    if !n.RangeIPV4.Packed() {
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

func (n *NfNATIPV4Range) SizeBytes() int {
    return 8 +
        1*4 +
        1*4
}

func (n *NfNATIPV4Range) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.MinIP[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(n.MaxIP[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MinPort))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MaxPort))
    dst = dst[2:]
    return dst
}

func (n *NfNATIPV4Range) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 4; idx++ {
        n.MinIP[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < 4; idx++ {
        n.MaxIP[idx] = src[0]
        src = src[1:]
    }
    n.MinPort = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.MaxPort = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NfNATIPV4Range) Packed() bool {
    return true
}

func (n *NfNATIPV4Range) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NfNATIPV4Range) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NfNATIPV4Range) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NfNATIPV4Range) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NfNATIPV4Range) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NfNATIPV4Range) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NfNATIPV4Range) WriteTo(writer io.Writer) (int64, error) {
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
func (tn *TableName) SizeBytes() int {
    return 1 * XT_TABLE_MAXNAMELEN
}

func (tn *TableName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        dst[0] = byte(tn[idx])
        dst = dst[1:]
    }
    return dst
}

func (tn *TableName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < XT_TABLE_MAXNAMELEN; idx++ {
        tn[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (tn *TableName) Packed() bool {
    return true
}

func (tn *TableName) MarshalUnsafe(dst []byte) []byte {
    size := tn.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&tn[0]), uintptr(size))
    return dst[size:]
}

func (tn *TableName) UnmarshalUnsafe(src []byte) []byte {
    size := tn.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(tn), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (tn *TableName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tn)))
    hdr.Len = tn.SizeBytes()
    hdr.Cap = tn.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(tn)
    return length, err
}

func (tn *TableName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tn.CopyOutN(cc, addr, tn.SizeBytes())
}

func (tn *TableName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tn)))
    hdr.Len = tn.SizeBytes()
    hdr.Cap = tn.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(tn)
    return length, err
}

func (tn *TableName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tn.CopyInN(cc, addr, tn.SizeBytes())
}

func (tn *TableName) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tn)))
    hdr.Len = tn.SizeBytes()
    hdr.Cap = tn.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(tn)
    return int64(length), err
}

func (x *XTCTTargetInfoV0) SizeBytes() int {
    return 12 +
        (*XTEntryTarget)(nil).SizeBytes() +
        1*16 +
        1*4 +
        1*8
}

func (x *XTCTTargetInfoV0) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.Flags))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.Zone))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.CTEvents))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.ExpEvents))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(x.Helper[idx])
        dst = dst[1:]
    }
    dst = dst[1*(4):]
    dst = dst[1*(8):]
    return dst
}

func (x *XTCTTargetInfoV0) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    x.Flags = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.Zone = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.CTEvents = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.ExpEvents = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        x.Helper[idx] = src[0]
        src = src[1:]
    }
    src = src[1*(4):]
    src = src[1*(8):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTCTTargetInfoV0) Packed() bool {
    return x.Target.Packed()
}

func (x *XTCTTargetInfoV0) MarshalUnsafe(dst []byte) []byte {
    if x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTCTTargetInfoV0) UnmarshalUnsafe(src []byte) []byte {
    if x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTCTTargetInfoV0) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTCTTargetInfoV0) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTCTTargetInfoV0) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTCTTargetInfoV0) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTCTTargetInfoV0) WriteTo(writer io.Writer) (int64, error) {
    if !x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTCounters) SizeBytes() int {
    return 16
}

func (x *XTCounters) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(x.Pcnt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(x.Bcnt))
    dst = dst[8:]
    return dst
}

func (x *XTCounters) UnmarshalBytes(src []byte) []byte {
    x.Pcnt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    x.Bcnt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTCounters) Packed() bool {
    return true
}

func (x *XTCounters) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTCounters) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTCounters) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTCounters) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTCounters) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTCounters) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTCounters) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTEntryMatch) SizeBytes() int {
    return 3 +
        (*ExtensionName)(nil).SizeBytes()
}

func (x *XTEntryMatch) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.MatchSize))
    dst = dst[2:]
    dst = x.Name.MarshalUnsafe(dst)
    dst[0] = byte(x.Revision)
    dst = dst[1:]
    return dst
}

func (x *XTEntryMatch) UnmarshalBytes(src []byte) []byte {
    x.MatchSize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = x.Name.UnmarshalUnsafe(src)
    x.Revision = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTEntryMatch) Packed() bool {
    return x.Name.Packed()
}

func (x *XTEntryMatch) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTEntryMatch) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTEntryMatch) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTEntryMatch) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTEntryMatch) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTEntryMatch) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTEntryMatch) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTEntryTarget) SizeBytes() int {
    return 3 +
        (*ExtensionName)(nil).SizeBytes()
}

func (x *XTEntryTarget) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.TargetSize))
    dst = dst[2:]
    dst = x.Name.MarshalUnsafe(dst)
    dst[0] = byte(x.Revision)
    dst = dst[1:]
    return dst
}

func (x *XTEntryTarget) UnmarshalBytes(src []byte) []byte {
    x.TargetSize = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = x.Name.UnmarshalUnsafe(src)
    x.Revision = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTEntryTarget) Packed() bool {
    return x.Name.Packed()
}

func (x *XTEntryTarget) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTEntryTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTEntryTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTEntryTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTEntryTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTEntryTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTEntryTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTErrorTarget) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*ErrorName)(nil).SizeBytes() +
        1*2
}

func (x *XTErrorTarget) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.Name.MarshalUnsafe(dst)
    dst = dst[1*(2):]
    return dst
}

func (x *XTErrorTarget) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.Name.UnmarshalUnsafe(src)
    src = src[1*(2):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTErrorTarget) Packed() bool {
    return x.Name.Packed() && x.Target.Packed()
}

func (x *XTErrorTarget) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTErrorTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTErrorTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTErrorTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTErrorTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTErrorTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTErrorTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() && x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTGetRevision) SizeBytes() int {
    return 1 +
        (*ExtensionName)(nil).SizeBytes()
}

func (x *XTGetRevision) MarshalBytes(dst []byte) []byte {
    dst = x.Name.MarshalUnsafe(dst)
    dst[0] = byte(x.Revision)
    dst = dst[1:]
    return dst
}

func (x *XTGetRevision) UnmarshalBytes(src []byte) []byte {
    src = x.Name.UnmarshalUnsafe(src)
    x.Revision = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTGetRevision) Packed() bool {
    return x.Name.Packed()
}

func (x *XTGetRevision) MarshalUnsafe(dst []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTGetRevision) UnmarshalUnsafe(src []byte) []byte {
    if x.Name.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTGetRevision) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTGetRevision) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTGetRevision) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Name.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTGetRevision) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTGetRevision) WriteTo(writer io.Writer) (int64, error) {
    if !x.Name.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTMarkMtinfo1) SizeBytes() int {
    return 9 +
        1*3
}

func (x *XTMarkMtinfo1) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.Mark))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.Mask))
    dst = dst[4:]
    dst[0] = byte(x.Invert)
    dst = dst[1:]
    dst = dst[1*(3):]
    return dst
}

func (x *XTMarkMtinfo1) UnmarshalBytes(src []byte) []byte {
    x.Mark = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.Mask = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.Invert = uint8(src[0])
    src = src[1:]
    src = src[1*(3):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTMarkMtinfo1) Packed() bool {
    return true
}

func (x *XTMarkMtinfo1) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTMarkMtinfo1) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTMarkMtinfo1) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTMarkMtinfo1) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTMarkMtinfo1) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTMarkMtinfo1) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTMarkMtinfo1) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTMultiport) SizeBytes() int {
    return 2 +
        2*XT_MULTI_PORTS
}

func (x *XTMultiport) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(x.Flags)
    dst = dst[1:]
    dst[0] = byte(x.Count)
    dst = dst[1:]
    for idx := 0; idx < XT_MULTI_PORTS; idx++ {
        hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.Ports[idx]))
        dst = dst[2:]
    }
    return dst
}

func (x *XTMultiport) UnmarshalBytes(src []byte) []byte {
    x.Flags = uint8(src[0])
    src = src[1:]
    x.Count = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < XT_MULTI_PORTS; idx++ {
        x.Ports[idx] = uint16(hostarch.ByteOrder.Uint16(src[:2]))
        src = src[2:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTMultiport) Packed() bool {
    return true
}

func (x *XTMultiport) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTMultiport) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTMultiport) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTMultiport) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTMultiport) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTMultiport) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTMultiport) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTMultiportV1) SizeBytes() int {
    return 3 +
        2*XT_MULTI_PORTS +
        1*XT_MULTI_PORTS
}

func (x *XTMultiportV1) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(x.Flags)
    dst = dst[1:]
    dst[0] = byte(x.Count)
    dst = dst[1:]
    for idx := 0; idx < XT_MULTI_PORTS; idx++ {
        hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.Ports[idx]))
        dst = dst[2:]
    }
    for idx := 0; idx < XT_MULTI_PORTS; idx++ {
        dst[0] = byte(x.Pflags[idx])
        dst = dst[1:]
    }
    dst[0] = byte(x.Invert)
    dst = dst[1:]
    return dst
}

func (x *XTMultiportV1) UnmarshalBytes(src []byte) []byte {
    x.Flags = uint8(src[0])
    src = src[1:]
    x.Count = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < XT_MULTI_PORTS; idx++ {
        x.Ports[idx] = uint16(hostarch.ByteOrder.Uint16(src[:2]))
        src = src[2:]
    }
    for idx := 0; idx < XT_MULTI_PORTS; idx++ {
        x.Pflags[idx] = uint8(src[0])
        src = src[1:]
    }
    x.Invert = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTMultiportV1) Packed() bool {
    return true
}

func (x *XTMultiportV1) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTMultiportV1) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTMultiportV1) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTMultiportV1) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTMultiportV1) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTMultiportV1) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTMultiportV1) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTNATTargetV0) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NfNATIPV4MultiRangeCompat)(nil).SizeBytes() +
        1*4
}

func (x *XTNATTargetV0) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.NfRange.MarshalUnsafe(dst)
    dst = dst[1*(4):]
    return dst
}

func (x *XTNATTargetV0) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.NfRange.UnmarshalUnsafe(src)
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTNATTargetV0) Packed() bool {
    return x.NfRange.Packed() && x.Target.Packed()
}

func (x *XTNATTargetV0) MarshalUnsafe(dst []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTNATTargetV0) UnmarshalUnsafe(src []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTNATTargetV0) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTNATTargetV0) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTNATTargetV0) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTNATTargetV0) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTNATTargetV0) WriteTo(writer io.Writer) (int64, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTNATTargetV1) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NFNATRange)(nil).SizeBytes()
}

func (x *XTNATTargetV1) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.Range.MarshalUnsafe(dst)
    return dst
}

func (x *XTNATTargetV1) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.Range.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTNATTargetV1) Packed() bool {
    return x.Range.Packed() && x.Target.Packed()
}

func (x *XTNATTargetV1) MarshalUnsafe(dst []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTNATTargetV1) UnmarshalUnsafe(src []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTNATTargetV1) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTNATTargetV1) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTNATTargetV1) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTNATTargetV1) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTNATTargetV1) WriteTo(writer io.Writer) (int64, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTNATTargetV2) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NFNATRange2)(nil).SizeBytes()
}

func (x *XTNATTargetV2) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.Range.MarshalUnsafe(dst)
    return dst
}

func (x *XTNATTargetV2) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.Range.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTNATTargetV2) Packed() bool {
    return x.Range.Packed() && x.Target.Packed()
}

func (x *XTNATTargetV2) MarshalUnsafe(dst []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTNATTargetV2) UnmarshalUnsafe(src []byte) []byte {
    if x.Range.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTNATTargetV2) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTNATTargetV2) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTNATTargetV2) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTNATTargetV2) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTNATTargetV2) WriteTo(writer io.Writer) (int64, error) {
    if !x.Range.Packed() && x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTOwnerMatchInfo) SizeBytes() int {
    return 18 +
        1*2
}

func (x *XTOwnerMatchInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.UIDMin))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.UIDMax))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.GIDMin))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.GIDMax))
    dst = dst[4:]
    dst[0] = byte(x.Match)
    dst = dst[1:]
    dst[0] = byte(x.Invert)
    dst = dst[1:]
    dst = dst[1*(2):]
    return dst
}

func (x *XTOwnerMatchInfo) UnmarshalBytes(src []byte) []byte {
    x.UIDMin = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.UIDMax = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.GIDMin = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.GIDMax = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    x.Match = uint8(src[0])
    src = src[1:]
    x.Invert = uint8(src[0])
    src = src[1:]
    src = src[1*(2):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTOwnerMatchInfo) Packed() bool {
    return true
}

func (x *XTOwnerMatchInfo) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTOwnerMatchInfo) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTOwnerMatchInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTOwnerMatchInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTOwnerMatchInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTOwnerMatchInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTOwnerMatchInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTRedirectTarget) SizeBytes() int {
    return 0 +
        (*XTEntryTarget)(nil).SizeBytes() +
        (*NfNATIPV4MultiRangeCompat)(nil).SizeBytes() +
        1*4
}

func (x *XTRedirectTarget) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    dst = x.NfRange.MarshalUnsafe(dst)
    dst = dst[1*(4):]
    return dst
}

func (x *XTRedirectTarget) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    src = x.NfRange.UnmarshalUnsafe(src)
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTRedirectTarget) Packed() bool {
    return x.NfRange.Packed() && x.Target.Packed()
}

func (x *XTRedirectTarget) MarshalUnsafe(dst []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTRedirectTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.NfRange.Packed() && x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTRedirectTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTRedirectTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTRedirectTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTRedirectTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTRedirectTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.NfRange.Packed() && x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTStandardTarget) SizeBytes() int {
    return 4 +
        (*XTEntryTarget)(nil).SizeBytes() +
        1*4
}

func (x *XTStandardTarget) MarshalBytes(dst []byte) []byte {
    dst = x.Target.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(x.Verdict))
    dst = dst[4:]
    dst = dst[1*(4):]
    return dst
}

func (x *XTStandardTarget) UnmarshalBytes(src []byte) []byte {
    src = x.Target.UnmarshalUnsafe(src)
    x.Verdict = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTStandardTarget) Packed() bool {
    return x.Target.Packed()
}

func (x *XTStandardTarget) MarshalUnsafe(dst []byte) []byte {
    if x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
        return dst[size:]
    }
    return x.MarshalBytes(dst)
}

func (x *XTStandardTarget) UnmarshalUnsafe(src []byte) []byte {
    if x.Target.Packed() {
        size := x.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return x.UnmarshalBytes(src)
}

func (x *XTStandardTarget) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        x.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTStandardTarget) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTStandardTarget) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !x.Target.Packed() {
        buf := cc.CopyScratchBuffer(x.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        x.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTStandardTarget) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTStandardTarget) WriteTo(writer io.Writer) (int64, error) {
    if !x.Target.Packed() {
        buf := make([]byte, x.SizeBytes())
        x.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTTCP) SizeBytes() int {
    return 12
}

func (x *XTTCP) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortEnd))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortEnd))
    dst = dst[2:]
    dst[0] = byte(x.Option)
    dst = dst[1:]
    dst[0] = byte(x.FlagMask)
    dst = dst[1:]
    dst[0] = byte(x.FlagCompare)
    dst = dst[1:]
    dst[0] = byte(x.InverseFlags)
    dst = dst[1:]
    return dst
}

func (x *XTTCP) UnmarshalBytes(src []byte) []byte {
    x.SourcePortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.SourcePortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.Option = uint8(src[0])
    src = src[1:]
    x.FlagMask = uint8(src[0])
    src = src[1:]
    x.FlagCompare = uint8(src[0])
    src = src[1:]
    x.InverseFlags = uint8(src[0])
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTTCP) Packed() bool {
    return true
}

func (x *XTTCP) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTTCP) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTTCP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTTCP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTTCP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTTCP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTTCP) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (x *XTUDP) SizeBytes() int {
    return 10
}

func (x *XTUDP) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.SourcePortEnd))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortStart))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(x.DestinationPortEnd))
    dst = dst[2:]
    dst[0] = byte(x.InverseFlags)
    dst = dst[1:]
    dst = dst[1:]
    return dst
}

func (x *XTUDP) UnmarshalBytes(src []byte) []byte {
    x.SourcePortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.SourcePortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortStart = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.DestinationPortEnd = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    x.InverseFlags = uint8(src[0])
    src = src[1:]
    src = src[1:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (x *XTUDP) Packed() bool {
    return true
}

func (x *XTUDP) MarshalUnsafe(dst []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(x), uintptr(size))
    return dst[size:]
}

func (x *XTUDP) UnmarshalUnsafe(src []byte) []byte {
    size := x.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(x), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (x *XTUDP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTUDP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyOutN(cc, addr, x.SizeBytes())
}

func (x *XTUDP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(x)
    return length, err
}

func (x *XTUDP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return x.CopyInN(cc, addr, x.SizeBytes())
}

func (x *XTUDP) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(x)))
    hdr.Len = x.SizeBytes()
    hdr.Cap = x.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(x)
    return int64(length), err
}

func (i *IP6TEntry) SizeBytes() int {
    return 12 +
        (*IP6TIP)(nil).SizeBytes() +
        1*4 +
        (*XTCounters)(nil).SizeBytes()
}

func (i *IP6TEntry) MarshalBytes(dst []byte) []byte {
    dst = i.IPv6.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NFCache))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.TargetOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.NextOffset))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Comeback))
    dst = dst[4:]
    dst = dst[1*(4):]
    dst = i.Counters.MarshalUnsafe(dst)
    return dst
}

func (i *IP6TEntry) UnmarshalBytes(src []byte) []byte {
    src = i.IPv6.UnmarshalUnsafe(src)
    i.NFCache = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.TargetOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.NextOffset = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Comeback = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    src = i.Counters.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TEntry) Packed() bool {
    return i.Counters.Packed() && i.IPv6.Packed()
}

func (i *IP6TEntry) MarshalUnsafe(dst []byte) []byte {
    if i.Counters.Packed() && i.IPv6.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IP6TEntry) UnmarshalUnsafe(src []byte) []byte {
    if i.Counters.Packed() && i.IPv6.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IP6TEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
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

func (i *IP6TEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IP6TEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
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

func (i *IP6TEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IP6TEntry) WriteTo(writer io.Writer) (int64, error) {
    if !i.Counters.Packed() && i.IPv6.Packed() {
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

func (i *IP6TIP) SizeBytes() int {
    return 5 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*IFNAMSIZ +
        1*3
}

func (i *IP6TIP) MarshalBytes(dst []byte) []byte {
    dst = i.Src.MarshalUnsafe(dst)
    dst = i.Dst.MarshalUnsafe(dst)
    dst = i.SrcMask.MarshalUnsafe(dst)
    dst = i.DstMask.MarshalUnsafe(dst)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterface[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.InputInterfaceMask[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        dst[0] = byte(i.OutputInterfaceMask[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Protocol))
    dst = dst[2:]
    dst[0] = byte(i.TOS)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.InverseFlags)
    dst = dst[1:]
    dst = dst[1*(3):]
    return dst
}

func (i *IP6TIP) UnmarshalBytes(src []byte) []byte {
    src = i.Src.UnmarshalUnsafe(src)
    src = i.Dst.UnmarshalUnsafe(src)
    src = i.SrcMask.UnmarshalUnsafe(src)
    src = i.DstMask.UnmarshalUnsafe(src)
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterface[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.InputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < IFNAMSIZ; idx++ {
        i.OutputInterfaceMask[idx] = src[0]
        src = src[1:]
    }
    i.Protocol = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.TOS = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.InverseFlags = uint8(src[0])
    src = src[1:]
    src = src[1*(3):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TIP) Packed() bool {
    return i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed()
}

func (i *IP6TIP) MarshalUnsafe(dst []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IP6TIP) UnmarshalUnsafe(src []byte) []byte {
    if i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IP6TIP) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
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

func (i *IP6TIP) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IP6TIP) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
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

func (i *IP6TIP) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IP6TIP) WriteTo(writer io.Writer) (int64, error) {
    if !i.Dst.Packed() && i.DstMask.Packed() && i.Src.Packed() && i.SrcMask.Packed() {
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

func (i *IP6TReplace) SizeBytes() int {
    return 24 +
        (*TableName)(nil).SizeBytes() +
        4*NF_INET_NUMHOOKS +
        4*NF_INET_NUMHOOKS
}

func (i *IP6TReplace) MarshalBytes(dst []byte) []byte {
    dst = i.Name.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.ValidHooks))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumEntries))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Size))
    dst = dst[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.HookEntry[idx]))
        dst = dst[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Underflow[idx]))
        dst = dst[4:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.NumCounters))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(i.Counters))
    dst = dst[8:]
    return dst
}

func (i *IP6TReplace) UnmarshalBytes(src []byte) []byte {
    src = i.Name.UnmarshalUnsafe(src)
    i.ValidHooks = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.NumEntries = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.HookEntry[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    for idx := 0; idx < NF_INET_NUMHOOKS; idx++ {
        i.Underflow[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    i.NumCounters = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Counters = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *IP6TReplace) Packed() bool {
    return i.Name.Packed()
}

func (i *IP6TReplace) MarshalUnsafe(dst []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *IP6TReplace) UnmarshalUnsafe(src []byte) []byte {
    if i.Name.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *IP6TReplace) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IP6TReplace) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *IP6TReplace) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Name.Packed() {
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

func (i *IP6TReplace) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *IP6TReplace) WriteTo(writer io.Writer) (int64, error) {
    if !i.Name.Packed() {
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

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIP6TEntry) Packed() bool {
    return false
}

func (ke *KernelIP6TEntry) MarshalUnsafe(dst []byte) []byte {
    return ke.MarshalBytes(dst)
}

func (ke *KernelIP6TEntry) UnmarshalUnsafe(src []byte) []byte {
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIP6TEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    ke.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (ke *KernelIP6TEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIP6TEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    ke.UnmarshalBytes(buf)
    return length, err
}

func (ke *KernelIP6TEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

func (ke *KernelIP6TEntry) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ke *KernelIP6TGetEntries) Packed() bool {
    return false
}

func (ke *KernelIP6TGetEntries) MarshalUnsafe(dst []byte) []byte {
    return ke.MarshalBytes(dst)
}

func (ke *KernelIP6TGetEntries) UnmarshalUnsafe(src []byte) []byte {
    return ke.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (ke *KernelIP6TGetEntries) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    ke.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (ke *KernelIP6TGetEntries) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyOutN(cc, addr, ke.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (ke *KernelIP6TGetEntries) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(ke.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    ke.UnmarshalBytes(buf)
    return length, err
}

func (ke *KernelIP6TGetEntries) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ke.CopyInN(cc, addr, ke.SizeBytes())
}

func (ke *KernelIP6TGetEntries) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, ke.SizeBytes())
    ke.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (n *NFNATRange) SizeBytes() int {
    return 8 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes()
}

func (n *NFNATRange) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.MinAddr.MarshalUnsafe(dst)
    dst = n.MaxAddr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MinProto))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MaxProto))
    dst = dst[2:]
    return dst
}

func (n *NFNATRange) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.MinAddr.UnmarshalUnsafe(src)
    src = n.MaxAddr.UnmarshalUnsafe(src)
    n.MinProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.MaxProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NFNATRange) Packed() bool {
    return n.MaxAddr.Packed() && n.MinAddr.Packed()
}

func (n *NFNATRange) MarshalUnsafe(dst []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NFNATRange) UnmarshalUnsafe(src []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NFNATRange) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
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

func (n *NFNATRange) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NFNATRange) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
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

func (n *NFNATRange) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NFNATRange) WriteTo(writer io.Writer) (int64, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
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

func (n *NFNATRange2) SizeBytes() int {
    return 10 +
        (*Inet6Addr)(nil).SizeBytes() +
        (*Inet6Addr)(nil).SizeBytes() +
        1*6
}

func (n *NFNATRange2) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Flags))
    dst = dst[4:]
    dst = n.MinAddr.MarshalUnsafe(dst)
    dst = n.MaxAddr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MinProto))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.MaxProto))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.BaseProto))
    dst = dst[2:]
    dst = dst[1*(6):]
    return dst
}

func (n *NFNATRange2) UnmarshalBytes(src []byte) []byte {
    n.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.MinAddr.UnmarshalUnsafe(src)
    src = n.MaxAddr.UnmarshalUnsafe(src)
    n.MinProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.MaxProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.BaseProto = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(6):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NFNATRange2) Packed() bool {
    return n.MaxAddr.Packed() && n.MinAddr.Packed()
}

func (n *NFNATRange2) MarshalUnsafe(dst []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NFNATRange2) UnmarshalUnsafe(src []byte) []byte {
    if n.MaxAddr.Packed() && n.MinAddr.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NFNATRange2) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
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

func (n *NFNATRange2) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NFNATRange2) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
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

func (n *NFNATRange2) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NFNATRange2) WriteTo(writer io.Writer) (int64, error) {
    if !n.MaxAddr.Packed() && n.MinAddr.Packed() {
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

func (n *NetlinkAttrHeader) SizeBytes() int {
    return 4
}

func (n *NetlinkAttrHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Length))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Type))
    dst = dst[2:]
    return dst
}

func (n *NetlinkAttrHeader) UnmarshalBytes(src []byte) []byte {
    n.Length = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetlinkAttrHeader) Packed() bool {
    return true
}

func (n *NetlinkAttrHeader) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NetlinkAttrHeader) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NetlinkAttrHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NetlinkAttrHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NetlinkAttrHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NetlinkAttrHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NetlinkAttrHeader) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (n *NetlinkErrorMessage) SizeBytes() int {
    return 4 +
        (*NetlinkMessageHeader)(nil).SizeBytes()
}

func (n *NetlinkErrorMessage) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Error))
    dst = dst[4:]
    dst = n.Header.MarshalUnsafe(dst)
    return dst
}

func (n *NetlinkErrorMessage) UnmarshalBytes(src []byte) []byte {
    n.Error = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = n.Header.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetlinkErrorMessage) Packed() bool {
    return n.Header.Packed()
}

func (n *NetlinkErrorMessage) MarshalUnsafe(dst []byte) []byte {
    if n.Header.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
        return dst[size:]
    }
    return n.MarshalBytes(dst)
}

func (n *NetlinkErrorMessage) UnmarshalUnsafe(src []byte) []byte {
    if n.Header.Packed() {
        size := n.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return n.UnmarshalBytes(src)
}

func (n *NetlinkErrorMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Header.Packed() {
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

func (n *NetlinkErrorMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NetlinkErrorMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !n.Header.Packed() {
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

func (n *NetlinkErrorMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NetlinkErrorMessage) WriteTo(writer io.Writer) (int64, error) {
    if !n.Header.Packed() {
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

func (n *NetlinkMessageHeader) SizeBytes() int {
    return 16
}

func (n *NetlinkMessageHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Length))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.Flags))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.Seq))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(n.PortID))
    dst = dst[4:]
    return dst
}

func (n *NetlinkMessageHeader) UnmarshalBytes(src []byte) []byte {
    n.Length = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.Flags = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    n.Seq = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    n.PortID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetlinkMessageHeader) Packed() bool {
    return true
}

func (n *NetlinkMessageHeader) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NetlinkMessageHeader) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NetlinkMessageHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NetlinkMessageHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NetlinkMessageHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NetlinkMessageHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NetlinkMessageHeader) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (s *SockAddrNetlink) SizeBytes() int {
    return 12
}

func (s *SockAddrNetlink) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.PortID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Groups))
    dst = dst[4:]
    return dst
}

func (s *SockAddrNetlink) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[2:]
    s.PortID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Groups = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrNetlink) Packed() bool {
    return true
}

func (s *SockAddrNetlink) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SockAddrNetlink) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SockAddrNetlink) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrNetlink) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockAddrNetlink) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrNetlink) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockAddrNetlink) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (n *NetFilterGenMsg) SizeBytes() int {
    return 4
}

func (n *NetFilterGenMsg) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(n.Family)
    dst = dst[1:]
    dst[0] = byte(n.Version)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(n.ResourceID))
    dst = dst[2:]
    return dst
}

func (n *NetFilterGenMsg) UnmarshalBytes(src []byte) []byte {
    n.Family = uint8(src[0])
    src = src[1:]
    n.Version = uint8(src[0])
    src = src[1:]
    n.ResourceID = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (n *NetFilterGenMsg) Packed() bool {
    return true
}

func (n *NetFilterGenMsg) MarshalUnsafe(dst []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(n), uintptr(size))
    return dst[size:]
}

func (n *NetFilterGenMsg) UnmarshalUnsafe(src []byte) []byte {
    size := n.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(n), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (n *NetFilterGenMsg) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NetFilterGenMsg) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyOutN(cc, addr, n.SizeBytes())
}

func (n *NetFilterGenMsg) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(n)
    return length, err
}

func (n *NetFilterGenMsg) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return n.CopyInN(cc, addr, n.SizeBytes())
}

func (n *NetFilterGenMsg) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(n)))
    hdr.Len = n.SizeBytes()
    hdr.Cap = n.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(n)
    return int64(length), err
}

func (i *InterfaceAddrMessage) SizeBytes() int {
    return 8
}

func (i *InterfaceAddrMessage) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Family)
    dst = dst[1:]
    dst[0] = byte(i.PrefixLen)
    dst = dst[1:]
    dst[0] = byte(i.Flags)
    dst = dst[1:]
    dst[0] = byte(i.Scope)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Index))
    dst = dst[4:]
    return dst
}

func (i *InterfaceAddrMessage) UnmarshalBytes(src []byte) []byte {
    i.Family = uint8(src[0])
    src = src[1:]
    i.PrefixLen = uint8(src[0])
    src = src[1:]
    i.Flags = uint8(src[0])
    src = src[1:]
    i.Scope = uint8(src[0])
    src = src[1:]
    i.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InterfaceAddrMessage) Packed() bool {
    return true
}

func (i *InterfaceAddrMessage) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *InterfaceAddrMessage) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *InterfaceAddrMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *InterfaceAddrMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *InterfaceAddrMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *InterfaceAddrMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *InterfaceAddrMessage) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *InterfaceInfoMessage) SizeBytes() int {
    return 16
}

func (i *InterfaceInfoMessage) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(i.Family)
    dst = dst[1:]
    dst = dst[1:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(i.Type))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Change))
    dst = dst[4:]
    return dst
}

func (i *InterfaceInfoMessage) UnmarshalBytes(src []byte) []byte {
    i.Family = uint8(src[0])
    src = src[1:]
    src = src[1:]
    i.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    i.Index = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    i.Change = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InterfaceInfoMessage) Packed() bool {
    return true
}

func (i *InterfaceInfoMessage) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *InterfaceInfoMessage) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *InterfaceInfoMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *InterfaceInfoMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *InterfaceInfoMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *InterfaceInfoMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *InterfaceInfoMessage) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (r *RouteMessage) SizeBytes() int {
    return 12
}

func (r *RouteMessage) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(r.Family)
    dst = dst[1:]
    dst[0] = byte(r.DstLen)
    dst = dst[1:]
    dst[0] = byte(r.SrcLen)
    dst = dst[1:]
    dst[0] = byte(r.TOS)
    dst = dst[1:]
    dst[0] = byte(r.Table)
    dst = dst[1:]
    dst[0] = byte(r.Protocol)
    dst = dst[1:]
    dst[0] = byte(r.Scope)
    dst = dst[1:]
    dst[0] = byte(r.Type)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Flags))
    dst = dst[4:]
    return dst
}

func (r *RouteMessage) UnmarshalBytes(src []byte) []byte {
    r.Family = uint8(src[0])
    src = src[1:]
    r.DstLen = uint8(src[0])
    src = src[1:]
    r.SrcLen = uint8(src[0])
    src = src[1:]
    r.TOS = uint8(src[0])
    src = src[1:]
    r.Table = uint8(src[0])
    src = src[1:]
    r.Protocol = uint8(src[0])
    src = src[1:]
    r.Scope = uint8(src[0])
    src = src[1:]
    r.Type = uint8(src[0])
    src = src[1:]
    r.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RouteMessage) Packed() bool {
    return true
}

func (r *RouteMessage) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

func (r *RouteMessage) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (r *RouteMessage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RouteMessage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RouteMessage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RouteMessage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RouteMessage) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (r *RtAttr) SizeBytes() int {
    return 4
}

func (r *RtAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(r.Len))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(r.Type))
    dst = dst[2:]
    return dst
}

func (r *RtAttr) UnmarshalBytes(src []byte) []byte {
    r.Len = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    r.Type = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RtAttr) Packed() bool {
    return true
}

func (r *RtAttr) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

func (r *RtAttr) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (r *RtAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RtAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RtAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RtAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RtAttr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (p *PollFD) SizeBytes() int {
    return 8
}

func (p *PollFD) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(p.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.Events))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(p.REvents))
    dst = dst[2:]
    return dst
}

func (p *PollFD) UnmarshalBytes(src []byte) []byte {
    p.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    p.Events = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    p.REvents = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PollFD) Packed() bool {
    return true
}

func (p *PollFD) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *PollFD) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *PollFD) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *PollFD) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *PollFD) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *PollFD) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *PollFD) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func CopyPollFDSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []PollFD) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyPollFDSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []PollFD) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafePollFDSlice(src []PollFD, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*PollFD)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafePollFDSlice(dst []PollFD, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*PollFD)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadPollFDSlice(src io.Reader, dst []PollFD) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WritePollFDSlice(dst io.Writer, src []PollFD) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*PollFD)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (r *RSeqCriticalSection) SizeBytes() int {
    return 32
}

func (r *RSeqCriticalSection) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Version))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(r.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.Start))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.PostCommitOffset))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.Abort))
    dst = dst[8:]
    return dst
}

func (r *RSeqCriticalSection) UnmarshalBytes(src []byte) []byte {
    r.Version = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    r.Start = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.PostCommitOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.Abort = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *RSeqCriticalSection) Packed() bool {
    return true
}

func (r *RSeqCriticalSection) MarshalUnsafe(dst []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
    return dst[size:]
}

func (r *RSeqCriticalSection) UnmarshalUnsafe(src []byte) []byte {
    size := r.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (r *RSeqCriticalSection) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RSeqCriticalSection) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *RSeqCriticalSection) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(r)
    return length, err
}

func (r *RSeqCriticalSection) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *RSeqCriticalSection) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(r)))
    hdr.Len = r.SizeBytes()
    hdr.Cap = r.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(r)
    return int64(length), err
}

func (r *Rusage) SizeBytes() int {
    return 112 +
        (*Timeval)(nil).SizeBytes() +
        (*Timeval)(nil).SizeBytes()
}

func (r *Rusage) MarshalBytes(dst []byte) []byte {
    dst = r.UTime.MarshalUnsafe(dst)
    dst = r.STime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MaxRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.IXRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.IDRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.ISRSS))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MinFlt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MajFlt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NSwap))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.InBlock))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.OuBlock))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MsgSnd))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.MsgRcv))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NSignals))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NVCSw))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(r.NIvCSw))
    dst = dst[8:]
    return dst
}

func (r *Rusage) UnmarshalBytes(src []byte) []byte {
    src = r.UTime.UnmarshalUnsafe(src)
    src = r.STime.UnmarshalUnsafe(src)
    r.MaxRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.IXRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.IDRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.ISRSS = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MinFlt = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MajFlt = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NSwap = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.InBlock = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.OuBlock = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MsgSnd = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.MsgRcv = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NSignals = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NVCSw = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    r.NIvCSw = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (r *Rusage) Packed() bool {
    return r.STime.Packed() && r.UTime.Packed()
}

func (r *Rusage) MarshalUnsafe(dst []byte) []byte {
    if r.STime.Packed() && r.UTime.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(r), uintptr(size))
        return dst[size:]
    }
    return r.MarshalBytes(dst)
}

func (r *Rusage) UnmarshalUnsafe(src []byte) []byte {
    if r.STime.Packed() && r.UTime.Packed() {
        size := r.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(r), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return r.UnmarshalBytes(src)
}

func (r *Rusage) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
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

func (r *Rusage) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyOutN(cc, addr, r.SizeBytes())
}

func (r *Rusage) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
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

func (r *Rusage) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return r.CopyInN(cc, addr, r.SizeBytes())
}

func (r *Rusage) WriteTo(writer io.Writer) (int64, error) {
    if !r.STime.Packed() && r.UTime.Packed() {
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

func (s *SchedAttr) SizeBytes() int {
    return 56
}

func (s *SchedAttr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Size))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SchedPolicy))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SchedFlags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SchedNice))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SchedPriority))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SchedRuntime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SchedDeadline))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SchedPeriod))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SchedUtilMin))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SchedUtilMax))
    dst = dst[4:]
    return dst
}

func (s *SchedAttr) UnmarshalBytes(src []byte) []byte {
    s.Size = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SchedPolicy = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SchedFlags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SchedNice = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SchedPriority = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SchedRuntime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SchedDeadline = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SchedPeriod = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SchedUtilMin = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SchedUtilMax = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SchedAttr) Packed() bool {
    return true
}

func (s *SchedAttr) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SchedAttr) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SchedAttr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SchedAttr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SchedAttr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SchedAttr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SchedAttr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (sd *SeccompData) SizeBytes() int {
    return 16 +
        8*6
}

func (sd *SeccompData) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sd.Nr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sd.Arch))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(sd.InstructionPointer))
    dst = dst[8:]
    for idx := 0; idx < 6; idx++ {
        hostarch.ByteOrder.PutUint64(dst[:8], uint64(sd.Args[idx]))
        dst = dst[8:]
    }
    return dst
}

func (sd *SeccompData) UnmarshalBytes(src []byte) []byte {
    sd.Nr = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sd.Arch = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    sd.InstructionPointer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    for idx := 0; idx < 6; idx++ {
        sd.Args[idx] = uint64(hostarch.ByteOrder.Uint64(src[:8]))
        src = src[8:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (sd *SeccompData) Packed() bool {
    return true
}

func (sd *SeccompData) MarshalUnsafe(dst []byte) []byte {
    size := sd.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(sd), uintptr(size))
    return dst[size:]
}

func (sd *SeccompData) UnmarshalUnsafe(src []byte) []byte {
    size := sd.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(sd), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (sd *SeccompData) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sd)))
    hdr.Len = sd.SizeBytes()
    hdr.Cap = sd.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(sd)
    return length, err
}

func (sd *SeccompData) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sd.CopyOutN(cc, addr, sd.SizeBytes())
}

func (sd *SeccompData) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sd)))
    hdr.Len = sd.SizeBytes()
    hdr.Cap = sd.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(sd)
    return length, err
}

func (sd *SeccompData) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sd.CopyInN(cc, addr, sd.SizeBytes())
}

func (sd *SeccompData) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sd)))
    hdr.Len = sd.SizeBytes()
    hdr.Cap = sd.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(sd)
    return int64(length), err
}

func (s *SeccompNotif) SizeBytes() int {
    return 16 +
        (*SeccompData)(nil).SizeBytes()
}

func (s *SeccompNotif) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Pid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    dst = s.Data.MarshalUnsafe(dst)
    return dst
}

func (s *SeccompNotif) UnmarshalBytes(src []byte) []byte {
    s.ID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Pid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = s.Data.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompNotif) Packed() bool {
    return s.Data.Packed()
}

func (s *SeccompNotif) MarshalUnsafe(dst []byte) []byte {
    if s.Data.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *SeccompNotif) UnmarshalUnsafe(src []byte) []byte {
    if s.Data.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *SeccompNotif) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Data.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SeccompNotif) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SeccompNotif) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Data.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SeccompNotif) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SeccompNotif) WriteTo(writer io.Writer) (int64, error) {
    if !s.Data.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SeccompNotifResp) SizeBytes() int {
    return 24
}

func (s *SeccompNotifResp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ID))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Val))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Error))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    return dst
}

func (s *SeccompNotifResp) UnmarshalBytes(src []byte) []byte {
    s.ID = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Val = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Error = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompNotifResp) Packed() bool {
    return true
}

func (s *SeccompNotifResp) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SeccompNotifResp) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SeccompNotifResp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SeccompNotifResp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SeccompNotifResp) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SeccompNotifResp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SeccompNotifResp) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SeccompNotifSizes) SizeBytes() int {
    return 6
}

func (s *SeccompNotifSizes) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Notif))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Notif_resp))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Data))
    dst = dst[2:]
    return dst
}

func (s *SeccompNotifSizes) UnmarshalBytes(src []byte) []byte {
    s.Notif = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Notif_resp = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Data = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SeccompNotifSizes) Packed() bool {
    return true
}

func (s *SeccompNotifSizes) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SeccompNotifSizes) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SeccompNotifSizes) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SeccompNotifSizes) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SeccompNotifSizes) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SeccompNotifSizes) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SeccompNotifSizes) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SemInfo) SizeBytes() int {
    return 40
}

func (s *SemInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMap))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMni))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMns))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMnu))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemMsl))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemOpm))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemUme))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemUsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemVmx))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.SemAem))
    dst = dst[4:]
    return dst
}

func (s *SemInfo) UnmarshalBytes(src []byte) []byte {
    s.SemMap = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMni = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMns = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMnu = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemMsl = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemOpm = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemUme = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemUsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemVmx = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.SemAem = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SemInfo) Packed() bool {
    return true
}

func (s *SemInfo) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SemInfo) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SemInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SemInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SemInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SemInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SemInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *Sembuf) SizeBytes() int {
    return 6
}

func (s *Sembuf) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.SemNum))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.SemOp))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.SemFlg))
    dst = dst[2:]
    return dst
}

func (s *Sembuf) UnmarshalBytes(src []byte) []byte {
    s.SemNum = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.SemOp = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.SemFlg = int16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sembuf) Packed() bool {
    return true
}

func (s *Sembuf) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *Sembuf) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *Sembuf) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Sembuf) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *Sembuf) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Sembuf) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *Sembuf) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func CopySembufSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Sembuf) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopySembufSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Sembuf) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeSembufSlice(src []Sembuf, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*Sembuf)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeSembufSlice(dst []Sembuf, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*Sembuf)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadSembufSlice(src io.Reader, dst []Sembuf) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteSembufSlice(dst io.Writer, src []Sembuf) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Sembuf)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (s *ShmInfo) SizeBytes() int {
    return 44 +
        1*4
}

func (s *ShmInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UsedIDs))
    dst = dst[4:]
    dst = dst[1*(4):]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmTot))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmRss))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSwp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SwapAttempts))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SwapSuccesses))
    dst = dst[8:]
    return dst
}

func (s *ShmInfo) UnmarshalBytes(src []byte) []byte {
    s.UsedIDs = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    s.ShmTot = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmRss = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmSwp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SwapAttempts = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SwapSuccesses = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmInfo) Packed() bool {
    return true
}

func (s *ShmInfo) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *ShmInfo) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *ShmInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *ShmInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *ShmInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *ShmInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *ShmInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *ShmParams) SizeBytes() int {
    return 40
}

func (s *ShmParams) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMax))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMin))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmMni))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSeg))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmAll))
    dst = dst[8:]
    return dst
}

func (s *ShmParams) UnmarshalBytes(src []byte) []byte {
    s.ShmMax = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmMin = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmMni = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmSeg = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.ShmAll = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmParams) Packed() bool {
    return true
}

func (s *ShmParams) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *ShmParams) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *ShmParams) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *ShmParams) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *ShmParams) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *ShmParams) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *ShmParams) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *ShmidDS) SizeBytes() int {
    return 40 +
        (*IPCPerm)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes()
}

func (s *ShmidDS) MarshalBytes(dst []byte) []byte {
    dst = s.ShmPerm.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmSegsz))
    dst = dst[8:]
    dst = s.ShmAtime.MarshalUnsafe(dst)
    dst = s.ShmDtime.MarshalUnsafe(dst)
    dst = s.ShmCtime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.ShmCpid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.ShmLpid))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.ShmNattach))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Unused4))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Unused5))
    dst = dst[8:]
    return dst
}

func (s *ShmidDS) UnmarshalBytes(src []byte) []byte {
    src = s.ShmPerm.UnmarshalUnsafe(src)
    s.ShmSegsz = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.ShmAtime.UnmarshalUnsafe(src)
    src = s.ShmDtime.UnmarshalUnsafe(src)
    src = s.ShmCtime.UnmarshalUnsafe(src)
    s.ShmCpid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ShmLpid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ShmNattach = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unused4 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Unused5 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *ShmidDS) Packed() bool {
    return s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed()
}

func (s *ShmidDS) MarshalUnsafe(dst []byte) []byte {
    if s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *ShmidDS) UnmarshalUnsafe(src []byte) []byte {
    if s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *ShmidDS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *ShmidDS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *ShmidDS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *ShmidDS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *ShmidDS) WriteTo(writer io.Writer) (int64, error) {
    if !s.ShmAtime.Packed() && s.ShmCtime.Packed() && s.ShmDtime.Packed() && s.ShmPerm.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SigAction) SizeBytes() int {
    return 24 +
        (*SignalSet)(nil).SizeBytes()
}

func (s *SigAction) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Handler))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Flags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Restorer))
    dst = dst[8:]
    dst = s.Mask.MarshalUnsafe(dst)
    return dst
}

func (s *SigAction) UnmarshalBytes(src []byte) []byte {
    s.Handler = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Restorer = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.Mask.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SigAction) Packed() bool {
    return s.Mask.Packed()
}

func (s *SigAction) MarshalUnsafe(dst []byte) []byte {
    if s.Mask.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *SigAction) UnmarshalUnsafe(src []byte) []byte {
    if s.Mask.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *SigAction) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Mask.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SigAction) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SigAction) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Mask.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SigAction) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SigAction) WriteTo(writer io.Writer) (int64, error) {
    if !s.Mask.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *Sigevent) SizeBytes() int {
    return 20 +
        1*44
}

func (s *Sigevent) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Value))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Notify))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Tid))
    dst = dst[4:]
    for idx := 0; idx < 44; idx++ {
        dst[0] = byte(s.UnRemainder[idx])
        dst = dst[1:]
    }
    return dst
}

func (s *Sigevent) UnmarshalBytes(src []byte) []byte {
    s.Value = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Signo = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Notify = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Tid = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 44; idx++ {
        s.UnRemainder[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Sigevent) Packed() bool {
    return true
}

func (s *Sigevent) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *Sigevent) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *Sigevent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Sigevent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *Sigevent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *Sigevent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *Sigevent) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SignalInfo) SizeBytes() int {
    return 16 +
        1*(128-16)
}

func (s *SignalInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Code))
    dst = dst[4:]
    dst = dst[4:]
    for idx := 0; idx < (128-16); idx++ {
        dst[0] = byte(s.Fields[idx])
        dst = dst[1:]
    }
    return dst
}

func (s *SignalInfo) UnmarshalBytes(src []byte) []byte {
    s.Signo = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Errno = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Code = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    for idx := 0; idx < (128-16); idx++ {
        s.Fields[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalInfo) Packed() bool {
    return true
}

func (s *SignalInfo) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SignalInfo) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SignalInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SignalInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SignalInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SignalInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SignalInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (s *SignalSet) SizeBytes() int {
    return 8
}

func (s *SignalSet) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*s))
    return dst[8:]
}

func (s *SignalSet) UnmarshalBytes(src []byte) []byte {
    *s = SignalSet(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalSet) Packed() bool {
    return true
}

func (s *SignalSet) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SignalSet) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SignalSet) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SignalSet) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SignalSet) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SignalSet) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SignalSet) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SignalStack) SizeBytes() int {
    return 24
}

func (s *SignalStack) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flags))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    return dst
}

func (s *SignalStack) UnmarshalBytes(src []byte) []byte {
    s.Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    s.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalStack) Packed() bool {
    return true
}

func (s *SignalStack) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SignalStack) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SignalStack) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SignalStack) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SignalStack) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SignalStack) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SignalStack) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SignalfdSiginfo) SizeBytes() int {
    return 82 +
        1*48
}

func (s *SignalfdSiginfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Signo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Errno))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Code))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.PID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.FD))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.TID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Band))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Overrun))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.TrapNo))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Status))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Int))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Ptr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.UTime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.STime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Addr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.AddrLSB))
    dst = dst[2:]
    dst = dst[1*(48):]
    return dst
}

func (s *SignalfdSiginfo) UnmarshalBytes(src []byte) []byte {
    s.Signo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Errno = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Code = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.PID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.FD = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.TID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Band = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Overrun = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.TrapNo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Status = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Int = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.Ptr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.UTime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.STime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Addr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.AddrLSB = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(48):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SignalfdSiginfo) Packed() bool {
    return false
}

func (s *SignalfdSiginfo) MarshalUnsafe(dst []byte) []byte {
    return s.MarshalBytes(dst)
}

func (s *SignalfdSiginfo) UnmarshalUnsafe(src []byte) []byte {
    return s.UnmarshalBytes(src)
}

func (s *SignalfdSiginfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(s.SizeBytes())
    s.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (s *SignalfdSiginfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SignalfdSiginfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(s.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf[:limit])
    s.UnmarshalBytes(buf)
    return length, err
}

func (s *SignalfdSiginfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SignalfdSiginfo) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, s.SizeBytes())
    s.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (c *ControlMessageCredentials) SizeBytes() int {
    return 12
}

func (c *ControlMessageCredentials) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.PID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.GID))
    dst = dst[4:]
    return dst
}

func (c *ControlMessageCredentials) UnmarshalBytes(src []byte) []byte {
    c.PID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageCredentials) Packed() bool {
    return true
}

func (c *ControlMessageCredentials) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *ControlMessageCredentials) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *ControlMessageCredentials) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageCredentials) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageCredentials) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageCredentials) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageCredentials) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (c *ControlMessageHeader) SizeBytes() int {
    return 16
}

func (c *ControlMessageHeader) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(c.Length))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Level))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.Type))
    dst = dst[4:]
    return dst
}

func (c *ControlMessageHeader) UnmarshalBytes(src []byte) []byte {
    c.Length = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    c.Level = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    c.Type = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageHeader) Packed() bool {
    return true
}

func (c *ControlMessageHeader) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *ControlMessageHeader) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *ControlMessageHeader) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageHeader) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageHeader) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageHeader) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageHeader) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (c *ControlMessageIPPacketInfo) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes()
}

func (c *ControlMessageIPPacketInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.NIC))
    dst = dst[4:]
    dst = c.LocalAddr.MarshalUnsafe(dst)
    dst = c.DestinationAddr.MarshalUnsafe(dst)
    return dst
}

func (c *ControlMessageIPPacketInfo) UnmarshalBytes(src []byte) []byte {
    c.NIC = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = c.LocalAddr.UnmarshalUnsafe(src)
    src = c.DestinationAddr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageIPPacketInfo) Packed() bool {
    return c.DestinationAddr.Packed() && c.LocalAddr.Packed()
}

func (c *ControlMessageIPPacketInfo) MarshalUnsafe(dst []byte) []byte {
    if c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    return c.MarshalBytes(dst)
}

func (c *ControlMessageIPPacketInfo) UnmarshalUnsafe(src []byte) []byte {
    if c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return c.UnmarshalBytes(src)
}

func (c *ControlMessageIPPacketInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        buf := cc.CopyScratchBuffer(c.SizeBytes())
        c.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageIPPacketInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageIPPacketInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        buf := cc.CopyScratchBuffer(c.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        c.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageIPPacketInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageIPPacketInfo) WriteTo(writer io.Writer) (int64, error) {
    if !c.DestinationAddr.Packed() && c.LocalAddr.Packed() {
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (c *ControlMessageIPv6PacketInfo) SizeBytes() int {
    return 4 +
        (*Inet6Addr)(nil).SizeBytes()
}

func (c *ControlMessageIPv6PacketInfo) MarshalBytes(dst []byte) []byte {
    dst = c.Addr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(c.NIC))
    dst = dst[4:]
    return dst
}

func (c *ControlMessageIPv6PacketInfo) UnmarshalBytes(src []byte) []byte {
    src = c.Addr.UnmarshalUnsafe(src)
    c.NIC = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ControlMessageIPv6PacketInfo) Packed() bool {
    return c.Addr.Packed()
}

func (c *ControlMessageIPv6PacketInfo) MarshalUnsafe(dst []byte) []byte {
    if c.Addr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
        return dst[size:]
    }
    return c.MarshalBytes(dst)
}

func (c *ControlMessageIPv6PacketInfo) UnmarshalUnsafe(src []byte) []byte {
    if c.Addr.Packed() {
        size := c.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return c.UnmarshalBytes(src)
}

func (c *ControlMessageIPv6PacketInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.Addr.Packed() {
        buf := cc.CopyScratchBuffer(c.SizeBytes())
        c.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageIPv6PacketInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageIPv6PacketInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !c.Addr.Packed() {
        buf := cc.CopyScratchBuffer(c.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        c.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ControlMessageIPv6PacketInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *ControlMessageIPv6PacketInfo) WriteTo(writer io.Writer) (int64, error) {
    if !c.Addr.Packed() {
        buf := make([]byte, c.SizeBytes())
        c.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (i *ICMP6Filter) SizeBytes() int {
    return 0 +
        4*8
}

func (i *ICMP6Filter) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 8; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.Filter[idx]))
        dst = dst[4:]
    }
    return dst
}

func (i *ICMP6Filter) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 8; idx++ {
        i.Filter[idx] = uint32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *ICMP6Filter) Packed() bool {
    return true
}

func (i *ICMP6Filter) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *ICMP6Filter) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *ICMP6Filter) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *ICMP6Filter) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *ICMP6Filter) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *ICMP6Filter) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *ICMP6Filter) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Inet6Addr) SizeBytes() int {
    return 1 * 16
}

func (i *Inet6Addr) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
    return dst
}

func (i *Inet6Addr) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 16; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inet6Addr) Packed() bool {
    return true
}

func (i *Inet6Addr) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&i[0]), uintptr(size))
    return dst[size:]
}

func (i *Inet6Addr) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *Inet6Addr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Inet6Addr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *Inet6Addr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Inet6Addr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *Inet6Addr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *Inet6MulticastRequest) SizeBytes() int {
    return 4 +
        (*Inet6Addr)(nil).SizeBytes()
}

func (i *Inet6MulticastRequest) MarshalBytes(dst []byte) []byte {
    dst = i.MulticastAddr.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.InterfaceIndex))
    dst = dst[4:]
    return dst
}

func (i *Inet6MulticastRequest) UnmarshalBytes(src []byte) []byte {
    src = i.MulticastAddr.UnmarshalUnsafe(src)
    i.InterfaceIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Inet6MulticastRequest) Packed() bool {
    return i.MulticastAddr.Packed()
}

func (i *Inet6MulticastRequest) MarshalUnsafe(dst []byte) []byte {
    if i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *Inet6MulticastRequest) UnmarshalUnsafe(src []byte) []byte {
    if i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *Inet6MulticastRequest) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.MulticastAddr.Packed() {
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

func (i *Inet6MulticastRequest) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *Inet6MulticastRequest) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.MulticastAddr.Packed() {
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

func (i *Inet6MulticastRequest) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *Inet6MulticastRequest) WriteTo(writer io.Writer) (int64, error) {
    if !i.MulticastAddr.Packed() {
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

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *InetAddr) SizeBytes() int {
    return 1 * 4
}

func (i *InetAddr) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < 4; idx++ {
        dst[0] = byte(i[idx])
        dst = dst[1:]
    }
    return dst
}

func (i *InetAddr) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < 4; idx++ {
        i[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetAddr) Packed() bool {
    return true
}

func (i *InetAddr) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&i[0]), uintptr(size))
    return dst[size:]
}

func (i *InetAddr) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *InetAddr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *InetAddr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *InetAddr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *InetAddr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *InetAddr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *InetMulticastRequest) SizeBytes() int {
    return 0 +
        (*InetAddr)(nil).SizeBytes() +
        (*InetAddr)(nil).SizeBytes()
}

func (i *InetMulticastRequest) MarshalBytes(dst []byte) []byte {
    dst = i.MulticastAddr.MarshalUnsafe(dst)
    dst = i.InterfaceAddr.MarshalUnsafe(dst)
    return dst
}

func (i *InetMulticastRequest) UnmarshalBytes(src []byte) []byte {
    src = i.MulticastAddr.UnmarshalUnsafe(src)
    src = i.InterfaceAddr.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetMulticastRequest) Packed() bool {
    return i.InterfaceAddr.Packed() && i.MulticastAddr.Packed()
}

func (i *InetMulticastRequest) MarshalUnsafe(dst []byte) []byte {
    if i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *InetMulticastRequest) UnmarshalUnsafe(src []byte) []byte {
    if i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *InetMulticastRequest) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
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

func (i *InetMulticastRequest) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *InetMulticastRequest) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
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

func (i *InetMulticastRequest) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *InetMulticastRequest) WriteTo(writer io.Writer) (int64, error) {
    if !i.InterfaceAddr.Packed() && i.MulticastAddr.Packed() {
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

func (i *InetMulticastRequestWithNIC) SizeBytes() int {
    return 4 +
        (*InetMulticastRequest)(nil).SizeBytes()
}

func (i *InetMulticastRequestWithNIC) MarshalBytes(dst []byte) []byte {
    dst = i.InetMulticastRequest.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(i.InterfaceIndex))
    dst = dst[4:]
    return dst
}

func (i *InetMulticastRequestWithNIC) UnmarshalBytes(src []byte) []byte {
    src = i.InetMulticastRequest.UnmarshalUnsafe(src)
    i.InterfaceIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *InetMulticastRequestWithNIC) Packed() bool {
    return i.InetMulticastRequest.Packed()
}

func (i *InetMulticastRequestWithNIC) MarshalUnsafe(dst []byte) []byte {
    if i.InetMulticastRequest.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *InetMulticastRequestWithNIC) UnmarshalUnsafe(src []byte) []byte {
    if i.InetMulticastRequest.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *InetMulticastRequestWithNIC) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InetMulticastRequest.Packed() {
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

func (i *InetMulticastRequestWithNIC) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *InetMulticastRequestWithNIC) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.InetMulticastRequest.Packed() {
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

func (i *InetMulticastRequestWithNIC) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *InetMulticastRequestWithNIC) WriteTo(writer io.Writer) (int64, error) {
    if !i.InetMulticastRequest.Packed() {
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

func (l *Linger) SizeBytes() int {
    return 8
}

func (l *Linger) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(l.OnOff))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(l.Linger))
    dst = dst[4:]
    return dst
}

func (l *Linger) UnmarshalBytes(src []byte) []byte {
    l.OnOff = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    l.Linger = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (l *Linger) Packed() bool {
    return true
}

func (l *Linger) MarshalUnsafe(dst []byte) []byte {
    size := l.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(l), uintptr(size))
    return dst[size:]
}

func (l *Linger) UnmarshalUnsafe(src []byte) []byte {
    size := l.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(l), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (l *Linger) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(l)
    return length, err
}

func (l *Linger) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return l.CopyOutN(cc, addr, l.SizeBytes())
}

func (l *Linger) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(l)
    return length, err
}

func (l *Linger) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return l.CopyInN(cc, addr, l.SizeBytes())
}

func (l *Linger) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(l)))
    hdr.Len = l.SizeBytes()
    hdr.Cap = l.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(l)
    return int64(length), err
}

func (s *SockAddrInet) SizeBytes() int {
    return 4 +
        (*InetAddr)(nil).SizeBytes() +
        1*8
}

func (s *SockAddrInet) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    dst = s.Addr.MarshalUnsafe(dst)
    dst = dst[1*(8):]
    return dst
}

func (s *SockAddrInet) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = s.Addr.UnmarshalUnsafe(src)
    src = src[1*(8):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet) Packed() bool {
    return s.Addr.Packed()
}

func (s *SockAddrInet) MarshalUnsafe(dst []byte) []byte {
    if s.Addr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *SockAddrInet) UnmarshalUnsafe(src []byte) []byte {
    if s.Addr.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *SockAddrInet) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Addr.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        s.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrInet) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockAddrInet) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.Addr.Packed() {
        buf := cc.CopyScratchBuffer(s.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        s.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrInet) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockAddrInet) WriteTo(writer io.Writer) (int64, error) {
    if !s.Addr.Packed() {
        buf := make([]byte, s.SizeBytes())
        s.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SockAddrInet6) SizeBytes() int {
    return 12 +
        1*16
}

func (s *SockAddrInet6) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Port))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Flowinfo))
    dst = dst[4:]
    for idx := 0; idx < 16; idx++ {
        dst[0] = byte(s.Addr[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Scope_id))
    dst = dst[4:]
    return dst
}

func (s *SockAddrInet6) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Port = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Flowinfo = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 16; idx++ {
        s.Addr[idx] = src[0]
        src = src[1:]
    }
    s.Scope_id = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrInet6) Packed() bool {
    return true
}

func (s *SockAddrInet6) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SockAddrInet6) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SockAddrInet6) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrInet6) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockAddrInet6) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrInet6) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockAddrInet6) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SockAddrLink) SizeBytes() int {
    return 12 +
        1*8
}

func (s *SockAddrLink) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Protocol))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.InterfaceIndex))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.ARPHardwareType))
    dst = dst[2:]
    dst[0] = byte(s.PacketType)
    dst = dst[1:]
    dst[0] = byte(s.HardwareAddrLen)
    dst = dst[1:]
    for idx := 0; idx < 8; idx++ {
        dst[0] = byte(s.HardwareAddr[idx])
        dst = dst[1:]
    }
    return dst
}

func (s *SockAddrLink) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.Protocol = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.InterfaceIndex = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.ARPHardwareType = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    s.PacketType = src[0]
    src = src[1:]
    s.HardwareAddrLen = src[0]
    src = src[1:]
    for idx := 0; idx < 8; idx++ {
        s.HardwareAddr[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrLink) Packed() bool {
    return true
}

func (s *SockAddrLink) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SockAddrLink) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SockAddrLink) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrLink) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockAddrLink) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrLink) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockAddrLink) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (s *SockAddrUnix) SizeBytes() int {
    return 2 +
        1*UnixPathMax
}

func (s *SockAddrUnix) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(s.Family))
    dst = dst[2:]
    for idx := 0; idx < UnixPathMax; idx++ {
        dst[0] = byte(s.Path[idx])
        dst = dst[1:]
    }
    return dst
}

func (s *SockAddrUnix) UnmarshalBytes(src []byte) []byte {
    s.Family = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    for idx := 0; idx < UnixPathMax; idx++ {
        s.Path[idx] = int8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SockAddrUnix) Packed() bool {
    return true
}

func (s *SockAddrUnix) MarshalUnsafe(dst []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
    return dst[size:]
}

func (s *SockAddrUnix) UnmarshalUnsafe(src []byte) []byte {
    size := s.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (s *SockAddrUnix) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrUnix) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SockAddrUnix) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(s)
    return length, err
}

func (s *SockAddrUnix) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SockAddrUnix) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(s)))
    hdr.Len = s.SizeBytes()
    hdr.Cap = s.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(s)
    return int64(length), err
}

func (t *TCPInfo) SizeBytes() int {
    return 224
}

func (t *TCPInfo) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(t.State)
    dst = dst[1:]
    dst[0] = byte(t.CaState)
    dst = dst[1:]
    dst[0] = byte(t.Retransmits)
    dst = dst[1:]
    dst[0] = byte(t.Probes)
    dst = dst[1:]
    dst[0] = byte(t.Backoff)
    dst = dst[1:]
    dst[0] = byte(t.Options)
    dst = dst[1:]
    dst[0] = byte(t.WindowScale)
    dst = dst[1:]
    dst[0] = byte(t.DeliveryRateAppLimited)
    dst = dst[1:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RTO))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ATO))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SndMss))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvMss))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Unacked))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Sacked))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Lost))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Retrans))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Fackets))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataSent))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckSent))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastDataRecv))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LastAckRecv))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.PMTU))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSsthresh))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RTT))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RTTVar))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SndSsthresh))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SndCwnd))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Advmss))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Reordering))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvRTT))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.RcvSpace))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TotalRetrans))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.PacingRate))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.MaxPacingRate))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesAcked))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesReceived))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SegsOut))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.SegsIn))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.NotSentBytes))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.MinRTT))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsIn))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DataSegsOut))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.DeliveryRate))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BusyTime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.RwndLimited))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.SndBufLimited))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Delivered))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DeliveredCE))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesSent))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.BytesRetrans))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.DSACKDups))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ReordSeen))
    dst = dst[4:]
    return dst
}

func (t *TCPInfo) UnmarshalBytes(src []byte) []byte {
    t.State = uint8(src[0])
    src = src[1:]
    t.CaState = uint8(src[0])
    src = src[1:]
    t.Retransmits = uint8(src[0])
    src = src[1:]
    t.Probes = uint8(src[0])
    src = src[1:]
    t.Backoff = uint8(src[0])
    src = src[1:]
    t.Options = uint8(src[0])
    src = src[1:]
    t.WindowScale = uint8(src[0])
    src = src[1:]
    t.DeliveryRateAppLimited = uint8(src[0])
    src = src[1:]
    t.RTO = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ATO = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndMss = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvMss = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Unacked = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Sacked = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Lost = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Retrans = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Fackets = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataSent = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckSent = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastDataRecv = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LastAckRecv = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PMTU = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSsthresh = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTT = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RTTVar = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndSsthresh = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SndCwnd = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Advmss = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Reordering = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvRTT = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.RcvSpace = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TotalRetrans = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.PacingRate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.MaxPacingRate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesAcked = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesReceived = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SegsOut = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.SegsIn = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.NotSentBytes = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.MinRTT = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsIn = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DataSegsOut = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DeliveryRate = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BusyTime = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.RwndLimited = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.SndBufLimited = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.Delivered = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.DeliveredCE = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.BytesSent = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.BytesRetrans = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.DSACKDups = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ReordSeen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TCPInfo) Packed() bool {
    return true
}

func (t *TCPInfo) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *TCPInfo) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *TCPInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TCPInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *TCPInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TCPInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *TCPInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (t *Tpacket2Hdr) SizeBytes() int {
    return 28 +
        1*4
}

func (t *Tpacket2Hdr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpStatus))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpLen))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpSnaplen))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(t.TpMac))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(t.TpNet))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpSec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpNSec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(t.TpVlanTci))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(t.TpVlanTpid))
    dst = dst[2:]
    dst = dst[1*(4):]
    return dst
}

func (t *Tpacket2Hdr) UnmarshalBytes(src []byte) []byte {
    t.TpStatus = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpSnaplen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpMac = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    t.TpNet = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    t.TpSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpNSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpVlanTci = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    t.TpVlanTpid = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Tpacket2Hdr) Packed() bool {
    return true
}

func (t *Tpacket2Hdr) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *Tpacket2Hdr) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *Tpacket2Hdr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *Tpacket2Hdr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *Tpacket2Hdr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *Tpacket2Hdr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *Tpacket2Hdr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (t *TpacketHdr) SizeBytes() int {
    return 28 +
        1*4
}

func (t *TpacketHdr) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(t.TpStatus))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpLen))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpSnaplen))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(t.TpMac))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(t.TpNet))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpSec))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpUsec))
    dst = dst[4:]
    dst = dst[1*(4):]
    return dst
}

func (t *TpacketHdr) UnmarshalBytes(src []byte) []byte {
    t.TpStatus = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    t.TpLen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpSnaplen = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpMac = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    t.TpNet = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    t.TpSec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpUsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[1*(4):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TpacketHdr) Packed() bool {
    return true
}

func (t *TpacketHdr) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *TpacketHdr) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *TpacketHdr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TpacketHdr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *TpacketHdr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TpacketHdr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *TpacketHdr) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (t *TpacketReq) SizeBytes() int {
    return 16
}

func (t *TpacketReq) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpBlockSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpBlockNr))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpFrameSize))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.TpFrameNr))
    dst = dst[4:]
    return dst
}

func (t *TpacketReq) UnmarshalBytes(src []byte) []byte {
    t.TpBlockSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpBlockNr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpFrameSize = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.TpFrameNr = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TpacketReq) Packed() bool {
    return true
}

func (t *TpacketReq) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *TpacketReq) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *TpacketReq) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TpacketReq) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *TpacketReq) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TpacketReq) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *TpacketReq) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (t *TpacketStats) SizeBytes() int {
    return 8
}

func (t *TpacketStats) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Packets))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.Dropped))
    dst = dst[4:]
    return dst
}

func (t *TpacketStats) UnmarshalBytes(src []byte) []byte {
    t.Packets = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.Dropped = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TpacketStats) Packed() bool {
    return true
}

func (t *TpacketStats) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *TpacketStats) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *TpacketStats) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TpacketStats) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *TpacketStats) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TpacketStats) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *TpacketStats) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (c *ClockT) SizeBytes() int {
    return 8
}

func (c *ClockT) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*c))
    return dst[8:]
}

func (c *ClockT) UnmarshalBytes(src []byte) []byte {
    *c = ClockT(int64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (c *ClockT) Packed() bool {
    return true
}

func (c *ClockT) MarshalUnsafe(dst []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(c), uintptr(size))
    return dst[size:]
}

func (c *ClockT) UnmarshalUnsafe(src []byte) []byte {
    size := c.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(c), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (c *ClockT) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ClockT) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyOutN(cc, addr, c.SizeBytes())
}

func (c *ClockT) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(c)
    return length, err
}

func (c *ClockT) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return c.CopyInN(cc, addr, c.SizeBytes())
}

func (c *ClockT) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(c)))
    hdr.Len = c.SizeBytes()
    hdr.Cap = c.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(c)
    return int64(length), err
}

func (i *ItimerVal) SizeBytes() int {
    return 0 +
        (*Timeval)(nil).SizeBytes() +
        (*Timeval)(nil).SizeBytes()
}

func (i *ItimerVal) MarshalBytes(dst []byte) []byte {
    dst = i.Interval.MarshalUnsafe(dst)
    dst = i.Value.MarshalUnsafe(dst)
    return dst
}

func (i *ItimerVal) UnmarshalBytes(src []byte) []byte {
    src = i.Interval.UnmarshalUnsafe(src)
    src = i.Value.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *ItimerVal) Packed() bool {
    return i.Interval.Packed() && i.Value.Packed()
}

func (i *ItimerVal) MarshalUnsafe(dst []byte) []byte {
    if i.Interval.Packed() && i.Value.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
        return dst[size:]
    }
    return i.MarshalBytes(dst)
}

func (i *ItimerVal) UnmarshalUnsafe(src []byte) []byte {
    if i.Interval.Packed() && i.Value.Packed() {
        size := i.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return i.UnmarshalBytes(src)
}

func (i *ItimerVal) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
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

func (i *ItimerVal) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *ItimerVal) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
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

func (i *ItimerVal) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *ItimerVal) WriteTo(writer io.Writer) (int64, error) {
    if !i.Interval.Packed() && i.Value.Packed() {
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

func (its *Itimerspec) SizeBytes() int {
    return 0 +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes()
}

func (its *Itimerspec) MarshalBytes(dst []byte) []byte {
    dst = its.Interval.MarshalUnsafe(dst)
    dst = its.Value.MarshalUnsafe(dst)
    return dst
}

func (its *Itimerspec) UnmarshalBytes(src []byte) []byte {
    src = its.Interval.UnmarshalUnsafe(src)
    src = its.Value.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (its *Itimerspec) Packed() bool {
    return its.Interval.Packed() && its.Value.Packed()
}

func (its *Itimerspec) MarshalUnsafe(dst []byte) []byte {
    if its.Interval.Packed() && its.Value.Packed() {
        size := its.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(its), uintptr(size))
        return dst[size:]
    }
    return its.MarshalBytes(dst)
}

func (its *Itimerspec) UnmarshalUnsafe(src []byte) []byte {
    if its.Interval.Packed() && its.Value.Packed() {
        size := its.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(its), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return its.UnmarshalBytes(src)
}

func (its *Itimerspec) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !its.Interval.Packed() && its.Value.Packed() {
        buf := cc.CopyScratchBuffer(its.SizeBytes())
        its.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(its)))
    hdr.Len = its.SizeBytes()
    hdr.Cap = its.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(its)
    return length, err
}

func (its *Itimerspec) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return its.CopyOutN(cc, addr, its.SizeBytes())
}

func (its *Itimerspec) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !its.Interval.Packed() && its.Value.Packed() {
        buf := cc.CopyScratchBuffer(its.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        its.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(its)))
    hdr.Len = its.SizeBytes()
    hdr.Cap = its.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(its)
    return length, err
}

func (its *Itimerspec) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return its.CopyInN(cc, addr, its.SizeBytes())
}

func (its *Itimerspec) WriteTo(writer io.Writer) (int64, error) {
    if !its.Interval.Packed() && its.Value.Packed() {
        buf := make([]byte, its.SizeBytes())
        its.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(its)))
    hdr.Len = its.SizeBytes()
    hdr.Cap = its.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(its)
    return int64(length), err
}

func (sxts *StatxTimestamp) SizeBytes() int {
    return 16
}

func (sxts *StatxTimestamp) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(sxts.Sec))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(sxts.Nsec))
    dst = dst[4:]
    dst = dst[4:]
    return dst
}

func (sxts *StatxTimestamp) UnmarshalBytes(src []byte) []byte {
    sxts.Sec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    sxts.Nsec = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (sxts *StatxTimestamp) Packed() bool {
    return true
}

func (sxts *StatxTimestamp) MarshalUnsafe(dst []byte) []byte {
    size := sxts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(sxts), uintptr(size))
    return dst[size:]
}

func (sxts *StatxTimestamp) UnmarshalUnsafe(src []byte) []byte {
    size := sxts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(sxts), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (sxts *StatxTimestamp) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sxts)))
    hdr.Len = sxts.SizeBytes()
    hdr.Cap = sxts.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(sxts)
    return length, err
}

func (sxts *StatxTimestamp) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sxts.CopyOutN(cc, addr, sxts.SizeBytes())
}

func (sxts *StatxTimestamp) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sxts)))
    hdr.Len = sxts.SizeBytes()
    hdr.Cap = sxts.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(sxts)
    return length, err
}

func (sxts *StatxTimestamp) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return sxts.CopyInN(cc, addr, sxts.SizeBytes())
}

func (sxts *StatxTimestamp) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(sxts)))
    hdr.Len = sxts.SizeBytes()
    hdr.Cap = sxts.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(sxts)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TimeT) SizeBytes() int {
    return 8
}

func (t *TimeT) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*t))
    return dst[8:]
}

func (t *TimeT) UnmarshalBytes(src []byte) []byte {
    *t = TimeT(int64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TimeT) Packed() bool {
    return true
}

func (t *TimeT) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *TimeT) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *TimeT) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TimeT) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *TimeT) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TimeT) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *TimeT) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (t *TimerID) SizeBytes() int {
    return 4
}

func (t *TimerID) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*t))
    return dst[4:]
}

func (t *TimerID) UnmarshalBytes(src []byte) []byte {
    *t = TimerID(int32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *TimerID) Packed() bool {
    return true
}

func (t *TimerID) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *TimerID) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *TimerID) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TimerID) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *TimerID) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *TimerID) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *TimerID) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (ts *Timespec) SizeBytes() int {
    return 16
}

func (ts *Timespec) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(ts.Sec))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(ts.Nsec))
    dst = dst[8:]
    return dst
}

func (ts *Timespec) UnmarshalBytes(src []byte) []byte {
    ts.Sec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    ts.Nsec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (ts *Timespec) Packed() bool {
    return true
}

func (ts *Timespec) MarshalUnsafe(dst []byte) []byte {
    size := ts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(ts), uintptr(size))
    return dst[size:]
}

func (ts *Timespec) UnmarshalUnsafe(src []byte) []byte {
    size := ts.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(ts), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (ts *Timespec) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ts)))
    hdr.Len = ts.SizeBytes()
    hdr.Cap = ts.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(ts)
    return length, err
}

func (ts *Timespec) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ts.CopyOutN(cc, addr, ts.SizeBytes())
}

func (ts *Timespec) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ts)))
    hdr.Len = ts.SizeBytes()
    hdr.Cap = ts.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(ts)
    return length, err
}

func (ts *Timespec) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return ts.CopyInN(cc, addr, ts.SizeBytes())
}

func (ts *Timespec) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(ts)))
    hdr.Len = ts.SizeBytes()
    hdr.Cap = ts.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(ts)
    return int64(length), err
}

func CopyTimespecSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Timespec) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyTimespecSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Timespec) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeTimespecSlice(src []Timespec, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*Timespec)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeTimespecSlice(dst []Timespec, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*Timespec)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadTimespecSlice(src io.Reader, dst []Timespec) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteTimespecSlice(dst io.Writer, src []Timespec) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timespec)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (tv *Timeval) SizeBytes() int {
    return 16
}

func (tv *Timeval) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(tv.Sec))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(tv.Usec))
    dst = dst[8:]
    return dst
}

func (tv *Timeval) UnmarshalBytes(src []byte) []byte {
    tv.Sec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    tv.Usec = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (tv *Timeval) Packed() bool {
    return true
}

func (tv *Timeval) MarshalUnsafe(dst []byte) []byte {
    size := tv.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(tv), uintptr(size))
    return dst[size:]
}

func (tv *Timeval) UnmarshalUnsafe(src []byte) []byte {
    size := tv.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(tv), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (tv *Timeval) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tv)))
    hdr.Len = tv.SizeBytes()
    hdr.Cap = tv.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(tv)
    return length, err
}

func (tv *Timeval) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tv.CopyOutN(cc, addr, tv.SizeBytes())
}

func (tv *Timeval) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tv)))
    hdr.Len = tv.SizeBytes()
    hdr.Cap = tv.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(tv)
    return length, err
}

func (tv *Timeval) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return tv.CopyInN(cc, addr, tv.SizeBytes())
}

func (tv *Timeval) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(tv)))
    hdr.Len = tv.SizeBytes()
    hdr.Cap = tv.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(tv)
    return int64(length), err
}

func CopyTimevalSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []Timeval) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyInBytes(addr, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func CopyTimevalSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []Timeval) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := cc.CopyOutBytes(addr, buf)
    runtime.KeepAlive(src)
    return length, err
}

func MarshalUnsafeTimevalSlice(src []Timeval, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*Timeval)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeTimevalSlice(dst []Timeval, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*Timeval)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadTimevalSlice(src io.Reader, dst []Timeval) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&dst)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := io.ReadFull(src, buf)
    runtime.KeepAlive(dst)
    return length, err
}

func WriteTimevalSlice(dst io.Writer, src []Timeval) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Timeval)(nil).SizeBytes()

    ptr := unsafe.Pointer(&src)
    val := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(val)
    hdr.Len = size * count
    hdr.Cap = size * count

    length, err := dst.Write(buf)
    runtime.KeepAlive(src)
    return length, err
}

func (t *Tms) SizeBytes() int {
    return 0 +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes() +
        (*ClockT)(nil).SizeBytes()
}

func (t *Tms) MarshalBytes(dst []byte) []byte {
    dst = t.UTime.MarshalUnsafe(dst)
    dst = t.STime.MarshalUnsafe(dst)
    dst = t.CUTime.MarshalUnsafe(dst)
    dst = t.CSTime.MarshalUnsafe(dst)
    return dst
}

func (t *Tms) UnmarshalBytes(src []byte) []byte {
    src = t.UTime.UnmarshalUnsafe(src)
    src = t.STime.UnmarshalUnsafe(src)
    src = t.CUTime.UnmarshalUnsafe(src)
    src = t.CSTime.UnmarshalUnsafe(src)
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Tms) Packed() bool {
    return t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed()
}

func (t *Tms) MarshalUnsafe(dst []byte) []byte {
    if t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        size := t.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
        return dst[size:]
    }
    return t.MarshalBytes(dst)
}

func (t *Tms) UnmarshalUnsafe(src []byte) []byte {
    if t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        size := t.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return t.UnmarshalBytes(src)
}

func (t *Tms) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        buf := cc.CopyScratchBuffer(t.SizeBytes())
        t.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *Tms) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *Tms) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        buf := cc.CopyScratchBuffer(t.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        t.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *Tms) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *Tms) WriteTo(writer io.Writer) (int64, error) {
    if !t.CSTime.Packed() && t.CUTime.Packed() && t.STime.Packed() && t.UTime.Packed() {
        buf := make([]byte, t.SizeBytes())
        t.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (u *Utime) SizeBytes() int {
    return 16
}

func (u *Utime) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Actime))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(u.Modtime))
    dst = dst[8:]
    return dst
}

func (u *Utime) UnmarshalBytes(src []byte) []byte {
    u.Actime = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    u.Modtime = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Utime) Packed() bool {
    return true
}

func (u *Utime) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

func (u *Utime) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (u *Utime) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Utime) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *Utime) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Utime) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *Utime) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

func (t *KernelTermios) SizeBytes() int {
    return 25 +
        1*NumControlCharacters
}

func (t *KernelTermios) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.InputFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.OutputFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ControlFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LocalFlags))
    dst = dst[4:]
    dst[0] = byte(t.LineDiscipline)
    dst = dst[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        dst[0] = byte(t.ControlCharacters[idx])
        dst = dst[1:]
    }
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.InputSpeed))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.OutputSpeed))
    dst = dst[4:]
    return dst
}

func (t *KernelTermios) UnmarshalBytes(src []byte) []byte {
    t.InputFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.OutputFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ControlFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LocalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LineDiscipline = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        t.ControlCharacters[idx] = uint8(src[0])
        src = src[1:]
    }
    t.InputSpeed = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.OutputSpeed = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *KernelTermios) Packed() bool {
    return true
}

func (t *KernelTermios) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *KernelTermios) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *KernelTermios) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *KernelTermios) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *KernelTermios) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *KernelTermios) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *KernelTermios) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (t *Termios) SizeBytes() int {
    return 17 +
        1*NumControlCharacters
}

func (t *Termios) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.InputFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.OutputFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.ControlFlags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(t.LocalFlags))
    dst = dst[4:]
    dst[0] = byte(t.LineDiscipline)
    dst = dst[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        dst[0] = byte(t.ControlCharacters[idx])
        dst = dst[1:]
    }
    return dst
}

func (t *Termios) UnmarshalBytes(src []byte) []byte {
    t.InputFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.OutputFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.ControlFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LocalFlags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    t.LineDiscipline = uint8(src[0])
    src = src[1:]
    for idx := 0; idx < NumControlCharacters; idx++ {
        t.ControlCharacters[idx] = uint8(src[0])
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (t *Termios) Packed() bool {
    return true
}

func (t *Termios) MarshalUnsafe(dst []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(t), uintptr(size))
    return dst[size:]
}

func (t *Termios) UnmarshalUnsafe(src []byte) []byte {
    size := t.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(t), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (t *Termios) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *Termios) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyOutN(cc, addr, t.SizeBytes())
}

func (t *Termios) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(t)
    return length, err
}

func (t *Termios) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return t.CopyInN(cc, addr, t.SizeBytes())
}

func (t *Termios) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(t)))
    hdr.Len = t.SizeBytes()
    hdr.Cap = t.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(t)
    return int64(length), err
}

func (w *Winsize) SizeBytes() int {
    return 8
}

func (w *Winsize) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Row))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Col))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Xpixel))
    dst = dst[2:]
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(w.Ypixel))
    dst = dst[2:]
    return dst
}

func (w *Winsize) UnmarshalBytes(src []byte) []byte {
    w.Row = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Col = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Xpixel = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    w.Ypixel = uint16(hostarch.ByteOrder.Uint16(src[:2]))
    src = src[2:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (w *Winsize) Packed() bool {
    return true
}

func (w *Winsize) MarshalUnsafe(dst []byte) []byte {
    size := w.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(w), uintptr(size))
    return dst[size:]
}

func (w *Winsize) UnmarshalUnsafe(src []byte) []byte {
    size := w.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(w), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (w *Winsize) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(w)
    return length, err
}

func (w *Winsize) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return w.CopyOutN(cc, addr, w.SizeBytes())
}

func (w *Winsize) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(w)
    return length, err
}

func (w *Winsize) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return w.CopyInN(cc, addr, w.SizeBytes())
}

func (w *Winsize) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(w)))
    hdr.Len = w.SizeBytes()
    hdr.Cap = w.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(w)
    return int64(length), err
}

func (u *UtsName) SizeBytes() int {
    return 0 +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1) +
        1*(UTSLen+1)
}

func (u *UtsName) MarshalBytes(dst []byte) []byte {
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Sysname[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Nodename[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Release[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Version[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Machine[idx])
        dst = dst[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        dst[0] = byte(u.Domainname[idx])
        dst = dst[1:]
    }
    return dst
}

func (u *UtsName) UnmarshalBytes(src []byte) []byte {
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Sysname[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Nodename[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Release[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Version[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Machine[idx] = src[0]
        src = src[1:]
    }
    for idx := 0; idx < (UTSLen+1); idx++ {
        u.Domainname[idx] = src[0]
        src = src[1:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *UtsName) Packed() bool {
    return true
}

func (u *UtsName) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

func (u *UtsName) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (u *UtsName) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *UtsName) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *UtsName) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *UtsName) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *UtsName) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

func (v *VFIODeviceInfo) SizeBytes() int {
    return 8 +
        (*VFIODeviceInfoMin)(nil).SizeBytes()
}

func (v *VFIODeviceInfo) MarshalBytes(dst []byte) []byte {
    dst = v.VFIODeviceInfoMin.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.CapOffset))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.pad))
    dst = dst[4:]
    return dst
}

func (v *VFIODeviceInfo) UnmarshalBytes(src []byte) []byte {
    src = v.VFIODeviceInfoMin.UnmarshalUnsafe(src)
    v.CapOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.pad = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIODeviceInfo) Packed() bool {
    return v.VFIODeviceInfoMin.Packed()
}

func (v *VFIODeviceInfo) MarshalUnsafe(dst []byte) []byte {
    if v.VFIODeviceInfoMin.Packed() {
        size := v.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
        return dst[size:]
    }
    return v.MarshalBytes(dst)
}

func (v *VFIODeviceInfo) UnmarshalUnsafe(src []byte) []byte {
    if v.VFIODeviceInfoMin.Packed() {
        size := v.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return v.UnmarshalBytes(src)
}

func (v *VFIODeviceInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !v.VFIODeviceInfoMin.Packed() {
        buf := cc.CopyScratchBuffer(v.SizeBytes())
        v.MarshalBytes(buf)
        return cc.CopyOutBytes(addr, buf[:limit])
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIODeviceInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIODeviceInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !v.VFIODeviceInfoMin.Packed() {
        buf := cc.CopyScratchBuffer(v.SizeBytes())
        length, err := cc.CopyInBytes(addr, buf[:limit])
        v.UnmarshalBytes(buf)
        return length, err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIODeviceInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIODeviceInfo) WriteTo(writer io.Writer) (int64, error) {
    if !v.VFIODeviceInfoMin.Packed() {
        buf := make([]byte, v.SizeBytes())
        v.MarshalBytes(buf)
        length, err := writer.Write(buf)
        return int64(length), err
    }

    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

func (v *VFIODeviceInfoMin) SizeBytes() int {
    return 16
}

func (v *VFIODeviceInfoMin) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.NumRegions))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.NumIrqs))
    dst = dst[4:]
    return dst
}

func (v *VFIODeviceInfoMin) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.NumRegions = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.NumIrqs = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIODeviceInfoMin) Packed() bool {
    return true
}

func (v *VFIODeviceInfoMin) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

func (v *VFIODeviceInfoMin) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (v *VFIODeviceInfoMin) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIODeviceInfoMin) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIODeviceInfoMin) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIODeviceInfoMin) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIODeviceInfoMin) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

func (v *VFIOIommuType1DmaMap) SizeBytes() int {
    return 32
}

func (v *VFIOIommuType1DmaMap) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Vaddr))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.IOVa))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Size))
    dst = dst[8:]
    return dst
}

func (v *VFIOIommuType1DmaMap) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Vaddr = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.IOVa = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIommuType1DmaMap) Packed() bool {
    return true
}

func (v *VFIOIommuType1DmaMap) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

func (v *VFIOIommuType1DmaMap) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (v *VFIOIommuType1DmaMap) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIommuType1DmaMap) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIOIommuType1DmaMap) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIommuType1DmaMap) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIOIommuType1DmaMap) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

func (v *VFIOIommuType1DmaUnmap) SizeBytes() int {
    return 24
}

func (v *VFIOIommuType1DmaUnmap) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.IOVa))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Size))
    dst = dst[8:]
    return dst
}

func (v *VFIOIommuType1DmaUnmap) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.IOVa = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIommuType1DmaUnmap) Packed() bool {
    return true
}

func (v *VFIOIommuType1DmaUnmap) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

func (v *VFIOIommuType1DmaUnmap) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (v *VFIOIommuType1DmaUnmap) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIommuType1DmaUnmap) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIOIommuType1DmaUnmap) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIommuType1DmaUnmap) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIOIommuType1DmaUnmap) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

func (v *VFIOIrqInfo) SizeBytes() int {
    return 16
}

func (v *VFIOIrqInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Count))
    dst = dst[4:]
    return dst
}

func (v *VFIOIrqInfo) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Count = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIrqInfo) Packed() bool {
    return true
}

func (v *VFIOIrqInfo) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

func (v *VFIOIrqInfo) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (v *VFIOIrqInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIrqInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIOIrqInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIrqInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIOIrqInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

func (v *VFIOIrqSet) SizeBytes() int {
    return 20
}

func (v *VFIOIrqSet) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Start))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Count))
    dst = dst[4:]
    return dst
}

func (v *VFIOIrqSet) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Start = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Count = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIOIrqSet) Packed() bool {
    return true
}

func (v *VFIOIrqSet) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

func (v *VFIOIrqSet) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (v *VFIOIrqSet) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIrqSet) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIOIrqSet) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIOIrqSet) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIOIrqSet) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

func (v *VFIORegionInfo) SizeBytes() int {
    return 32
}

func (v *VFIORegionInfo) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Argsz))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Flags))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.Index))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(v.CapOffset))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(v.Offset))
    dst = dst[8:]
    return dst
}

func (v *VFIORegionInfo) UnmarshalBytes(src []byte) []byte {
    v.Argsz = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Index = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.CapOffset = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    v.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    v.Offset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (v *VFIORegionInfo) Packed() bool {
    return true
}

func (v *VFIORegionInfo) MarshalUnsafe(dst []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(v), uintptr(size))
    return dst[size:]
}

func (v *VFIORegionInfo) UnmarshalUnsafe(src []byte) []byte {
    size := v.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(v), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (v *VFIORegionInfo) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIORegionInfo) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyOutN(cc, addr, v.SizeBytes())
}

func (v *VFIORegionInfo) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(v)
    return length, err
}

func (v *VFIORegionInfo) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return v.CopyInN(cc, addr, v.SizeBytes())
}

func (v *VFIORegionInfo) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(v)))
    hdr.Len = v.SizeBytes()
    hdr.Cap = v.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(v)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *PosixACLXattr) Packed() bool {
    return false
}

func (a *PosixACLXattr) MarshalUnsafe(dst []byte) []byte {
    return a.MarshalBytes(dst)
}

func (a *PosixACLXattr) UnmarshalUnsafe(src []byte) []byte {
    return a.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (a *PosixACLXattr) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(a.SizeBytes())
    a.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (a *PosixACLXattr) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (a *PosixACLXattr) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(a.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    a.UnmarshalBytes(buf)
    return length, err
}

func (a *PosixACLXattr) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

func (a *PosixACLXattr) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, a.SizeBytes())
    a.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (a *PosixACLXattrEntry) Packed() bool {
    return false
}

func (a *PosixACLXattrEntry) MarshalUnsafe(dst []byte) []byte {
    return a.MarshalBytes(dst)
}

func (a *PosixACLXattrEntry) UnmarshalUnsafe(src []byte) []byte {
    return a.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
//go:nosplit
func (a *PosixACLXattrEntry) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(a.SizeBytes())
    a.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (a *PosixACLXattrEntry) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyOutN(cc, addr, a.SizeBytes())
}

// CopyInN implements marshal.Marshallable.CopyInN.
//go:nosplit
func (a *PosixACLXattrEntry) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(a.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf)
    a.UnmarshalBytes(buf)
    return length, err
}

func (a *PosixACLXattrEntry) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return a.CopyInN(cc, addr, a.SizeBytes())
}

func (a *PosixACLXattrEntry) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, a.SizeBytes())
    a.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

