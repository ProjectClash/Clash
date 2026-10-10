
package gasket

import (
    "github.com/metacubex/gvisor/pkg/gohacks"
    "github.com/metacubex/gvisor/pkg/hostarch"
    "github.com/metacubex/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

var _ marshal.Marshallable = (*GasketInterruptEventFd)(nil)
var _ marshal.Marshallable = (*GasketInterruptMapping)(nil)
var _ marshal.Marshallable = (*GasketPageTableDmaBufIoctl)(nil)
var _ marshal.Marshallable = (*GasketPageTableIoctl)(nil)

func (g *GasketInterruptEventFd) SizeBytes() int {
    return 16
}

func (g *GasketInterruptEventFd) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.Interrupt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.EventFD))
    dst = dst[8:]
    return dst
}

func (g *GasketInterruptEventFd) UnmarshalBytes(src []byte) []byte {
    g.Interrupt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.EventFD = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketInterruptEventFd) Packed() bool {
    return true
}

func (g *GasketInterruptEventFd) MarshalUnsafe(dst []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
    return dst[size:]
}

func (g *GasketInterruptEventFd) UnmarshalUnsafe(src []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (g *GasketInterruptEventFd) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(g)
    return length, err
}

func (g *GasketInterruptEventFd) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

func (g *GasketInterruptEventFd) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(g)
    return length, err
}

func (g *GasketInterruptEventFd) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

func (g *GasketInterruptEventFd) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(g)
    return int64(length), err
}

func (g *GasketInterruptMapping) SizeBytes() int {
    return 32
}

func (g *GasketInterruptMapping) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.Interrupt))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.EventFD))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.BarIndex))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.RegOffset))
    dst = dst[8:]
    return dst
}

func (g *GasketInterruptMapping) UnmarshalBytes(src []byte) []byte {
    g.Interrupt = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.EventFD = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.BarIndex = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.RegOffset = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketInterruptMapping) Packed() bool {
    return true
}

func (g *GasketInterruptMapping) MarshalUnsafe(dst []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
    return dst[size:]
}

func (g *GasketInterruptMapping) UnmarshalUnsafe(src []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (g *GasketInterruptMapping) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(g)
    return length, err
}

func (g *GasketInterruptMapping) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

func (g *GasketInterruptMapping) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(g)
    return length, err
}

func (g *GasketInterruptMapping) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

func (g *GasketInterruptMapping) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(g)
    return int64(length), err
}

func (g *GasketPageTableDmaBufIoctl) SizeBytes() int {
    return 20
}

func (g *GasketPageTableDmaBufIoctl) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.PageTableIndex))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.DeviceAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(g.DMABufID))
    dst = dst[4:]
    return dst
}

func (g *GasketPageTableDmaBufIoctl) UnmarshalBytes(src []byte) []byte {
    g.PageTableIndex = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.DeviceAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.DMABufID = int32(hostarch.ByteOrder.Uint32(src[:4]))
    src = src[4:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketPageTableDmaBufIoctl) Packed() bool {
    return false
}

func (g *GasketPageTableDmaBufIoctl) MarshalUnsafe(dst []byte) []byte {
    return g.MarshalBytes(dst)
}

func (g *GasketPageTableDmaBufIoctl) UnmarshalUnsafe(src []byte) []byte {
    return g.UnmarshalBytes(src)
}

func (g *GasketPageTableDmaBufIoctl) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(g.SizeBytes())
    g.MarshalBytes(buf)
    return cc.CopyOutBytes(addr, buf[:limit])
}

func (g *GasketPageTableDmaBufIoctl) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

func (g *GasketPageTableDmaBufIoctl) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    buf := cc.CopyScratchBuffer(g.SizeBytes())
    length, err := cc.CopyInBytes(addr, buf[:limit])
    g.UnmarshalBytes(buf)
    return length, err
}

func (g *GasketPageTableDmaBufIoctl) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

func (g *GasketPageTableDmaBufIoctl) WriteTo(writer io.Writer) (int64, error) {
    buf := make([]byte, g.SizeBytes())
    g.MarshalBytes(buf)
    length, err := writer.Write(buf)
    return int64(length), err
}

func (g *GasketPageTableIoctl) SizeBytes() int {
    return 32
}

func (g *GasketPageTableIoctl) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.PageTableIndex))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.Size))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.HostAddress))
    dst = dst[8:]
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(g.DeviceAddress))
    dst = dst[8:]
    return dst
}

func (g *GasketPageTableIoctl) UnmarshalBytes(src []byte) []byte {
    g.PageTableIndex = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.Size = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.HostAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    g.DeviceAddress = uint64(hostarch.ByteOrder.Uint64(src[:8]))
    src = src[8:]
    return src
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (g *GasketPageTableIoctl) Packed() bool {
    return true
}

func (g *GasketPageTableIoctl) MarshalUnsafe(dst []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(g), uintptr(size))
    return dst[size:]
}

func (g *GasketPageTableIoctl) UnmarshalUnsafe(src []byte) []byte {
    size := g.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(g), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (g *GasketPageTableIoctl) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(g)
    return length, err
}

func (g *GasketPageTableIoctl) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyOutN(cc, addr, g.SizeBytes())
}

func (g *GasketPageTableIoctl) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(g)
    return length, err
}

func (g *GasketPageTableIoctl) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return g.CopyInN(cc, addr, g.SizeBytes())
}

func (g *GasketPageTableIoctl) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(g)))
    hdr.Len = g.SizeBytes()
    hdr.Cap = g.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(g)
    return int64(length), err
}

