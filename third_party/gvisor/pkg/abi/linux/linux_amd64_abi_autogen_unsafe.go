

//go:build amd64 && amd64 && amd64 && amd64 && amd64 && amd64
// +build amd64,amd64,amd64,amd64,amd64,amd64

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

var _ marshal.Marshallable = (*EpollEvent)(nil)
var _ marshal.Marshallable = (*IPCPerm)(nil)
var _ marshal.Marshallable = (*PtraceRegs)(nil)
var _ marshal.Marshallable = (*SemidDS)(nil)
var _ marshal.Marshallable = (*Stat)(nil)
var _ marshal.Marshallable = (*TimeT)(nil)
var _ marshal.Marshallable = (*Timespec)(nil)

func (e *EpollEvent) SizeBytes() int {
    return 4 +
        4*2
}

func (e *EpollEvent) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Events))
    dst = dst[4:]
    for idx := 0; idx < 2; idx++ {
        hostarch.ByteOrder.PutUint32(dst[:4], uint32(e.Data[idx]))
        dst = dst[4:]
    }
    return dst
}

func (e *EpollEvent) UnmarshalBytes(src []byte) []byte {
    e.Events = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    for idx := 0; idx < 2; idx++ {
        e.Data[idx] = int32(hostarch.ByteOrder.Uint32(src[:4]))
        src = src[4:]
    }
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (e *EpollEvent) Packed() bool {
    return true
}

func (e *EpollEvent) MarshalUnsafe(dst []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(e), uintptr(size))
    return dst[size:]
}

func (e *EpollEvent) UnmarshalUnsafe(src []byte) []byte {
    size := e.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(e), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (e *EpollEvent) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EpollEvent) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyOutN(cc, addr, e.SizeBytes())
}

func (e *EpollEvent) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(e)
    return length, err
}

func (e *EpollEvent) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return e.CopyInN(cc, addr, e.SizeBytes())
}

func (e *EpollEvent) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(e)))
    hdr.Len = e.SizeBytes()
    hdr.Cap = e.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(e)
    return int64(length), err
}

func CopyEpollEventSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []EpollEvent) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

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

func CopyEpollEventSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []EpollEvent) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

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

func MarshalUnsafeEpollEventSlice(src []EpollEvent, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }

    size := (*EpollEvent)(nil).SizeBytes()
    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeEpollEventSlice(dst []EpollEvent, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }

    size := (*EpollEvent)(nil).SizeBytes()
    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

func ReadEpollEventSlice(src io.Reader, dst []EpollEvent) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

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

func WriteEpollEventSlice(dst io.Writer, src []EpollEvent) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*EpollEvent)(nil).SizeBytes()

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

func (s *Stat) SizeBytes() int {
    return 72 +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes() +
        (*Timespec)(nil).SizeBytes() +
        8*3
}

func (s *Stat) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Dev))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Ino))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Nlink))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.Mode))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.UID))
    dst = dst[4:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(s.GID))
    dst = dst[4:]
    dst = dst[4:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Rdev))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blksize))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.Blocks))
    dst = dst[8:]
    dst = s.ATime.MarshalUnsafe(dst)
    dst = s.MTime.MarshalUnsafe(dst)
    dst = s.CTime.MarshalUnsafe(dst)
    dst = dst[8*(3):]
    return dst
}

func (s *Stat) UnmarshalBytes(src []byte) []byte {
    s.Dev = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Ino = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Nlink = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Mode = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.UID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    s.GID = uint32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    src = src[4:]
    s.Rdev = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Size = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blksize = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.Blocks = int64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.ATime.UnmarshalUnsafe(src)
    src = s.MTime.UnmarshalUnsafe(src)
    src = s.CTime.UnmarshalUnsafe(src)
    src = src[8*(3):]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *Stat) Packed() bool {
    return s.ATime.Packed() && s.CTime.Packed() && s.MTime.Packed()
}

func (s *Stat) MarshalUnsafe(dst []byte) []byte {
    if s.ATime.Packed() && s.CTime.Packed() && s.MTime.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *Stat) UnmarshalUnsafe(src []byte) []byte {
    if s.ATime.Packed() && s.CTime.Packed() && s.MTime.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *Stat) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.ATime.Packed() && s.CTime.Packed() && s.MTime.Packed() {
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

func (s *Stat) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *Stat) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.ATime.Packed() && s.CTime.Packed() && s.MTime.Packed() {
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

func (s *Stat) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *Stat) WriteTo(writer io.Writer) (int64, error) {
    if !s.ATime.Packed() && s.CTime.Packed() && s.MTime.Packed() {
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

func (p *PtraceRegs) SizeBytes() int {
    return 216
}

func (p *PtraceRegs) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R15))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R14))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R13))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R12))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rbp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rbx))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R11))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R10))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R9))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.R8))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rax))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rcx))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rdx))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rsi))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rdi))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Orig_rax))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rip))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Cs))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Eflags))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Rsp))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Ss))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Fs_base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Gs_base))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Ds))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Es))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Fs))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(p.Gs))
    dst = dst[8:]
    return dst
}

func (p *PtraceRegs) UnmarshalBytes(src []byte) []byte {
    p.R15 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R14 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R13 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R12 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rbp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rbx = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R11 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R10 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R9 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.R8 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rax = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rcx = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rdx = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rsi = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rdi = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Orig_rax = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rip = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Cs = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Eflags = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Rsp = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Ss = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Fs_base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Gs_base = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Ds = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Es = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Fs = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    p.Gs = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (p *PtraceRegs) Packed() bool {
    return true
}

func (p *PtraceRegs) MarshalUnsafe(dst []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(p), uintptr(size))
    return dst[size:]
}

func (p *PtraceRegs) UnmarshalUnsafe(src []byte) []byte {
    size := p.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(p), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (p *PtraceRegs) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *PtraceRegs) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyOutN(cc, addr, p.SizeBytes())
}

func (p *PtraceRegs) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(p)
    return length, err
}

func (p *PtraceRegs) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return p.CopyInN(cc, addr, p.SizeBytes())
}

func (p *PtraceRegs) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(p)))
    hdr.Len = p.SizeBytes()
    hdr.Cap = p.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(p)
    return int64(length), err
}

func (s *SemidDS) SizeBytes() int {
    return 40 +
        (*IPCPerm)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes() +
        (*TimeT)(nil).SizeBytes()
}

func (s *SemidDS) MarshalBytes(dst []byte) []byte {
    dst = s.SemPerm.MarshalUnsafe(dst)
    dst = s.SemOTime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.unused1))
    dst = dst[8:]
    dst = s.SemCTime.MarshalUnsafe(dst)
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.unused2))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.SemNSems))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.unused3))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(s.unused4))
    dst = dst[8:]
    return dst
}

func (s *SemidDS) UnmarshalBytes(src []byte) []byte {
    src = s.SemPerm.UnmarshalUnsafe(src)
    src = s.SemOTime.UnmarshalUnsafe(src)
    s.unused1 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    src = s.SemCTime.UnmarshalUnsafe(src)
    s.unused2 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.SemNSems = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.unused3 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    s.unused4 = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (s *SemidDS) Packed() bool {
    return s.SemCTime.Packed() && s.SemOTime.Packed() && s.SemPerm.Packed()
}

func (s *SemidDS) MarshalUnsafe(dst []byte) []byte {
    if s.SemCTime.Packed() && s.SemOTime.Packed() && s.SemPerm.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(s), uintptr(size))
        return dst[size:]
    }
    return s.MarshalBytes(dst)
}

func (s *SemidDS) UnmarshalUnsafe(src []byte) []byte {
    if s.SemCTime.Packed() && s.SemOTime.Packed() && s.SemPerm.Packed() {
        size := s.SizeBytes()
        gohacks.Memmove(unsafe.Pointer(s), unsafe.Pointer(&src[0]), uintptr(size))
        return src[size:]
    }
    return s.UnmarshalBytes(src)
}

func (s *SemidDS) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.SemCTime.Packed() && s.SemOTime.Packed() && s.SemPerm.Packed() {
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

func (s *SemidDS) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyOutN(cc, addr, s.SizeBytes())
}

func (s *SemidDS) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    if !s.SemCTime.Packed() && s.SemOTime.Packed() && s.SemPerm.Packed() {
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

func (s *SemidDS) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return s.CopyInN(cc, addr, s.SizeBytes())
}

func (s *SemidDS) WriteTo(writer io.Writer) (int64, error) {
    if !s.SemCTime.Packed() && s.SemOTime.Packed() && s.SemPerm.Packed() {
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

