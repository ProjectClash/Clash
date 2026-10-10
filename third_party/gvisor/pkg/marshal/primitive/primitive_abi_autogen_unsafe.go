
package primitive

import (
    "github.com/metacubex/gvisor/pkg/gohacks"
    "github.com/metacubex/gvisor/pkg/hostarch"
    "github.com/metacubex/gvisor/pkg/marshal"
    "io"
    "reflect"
    "runtime"
    "unsafe"
)

var _ marshal.Marshallable = (*Int16)(nil)
var _ marshal.Marshallable = (*Int32)(nil)
var _ marshal.Marshallable = (*Int64)(nil)
var _ marshal.Marshallable = (*Int8)(nil)
var _ marshal.Marshallable = (*Uint16)(nil)
var _ marshal.Marshallable = (*Uint32)(nil)
var _ marshal.Marshallable = (*Uint64)(nil)
var _ marshal.Marshallable = (*Uint8)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Int16) SizeBytes() int {
    return 2
}

func (i *Int16) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(*i))
    return dst[2:]
}

func (i *Int16) UnmarshalBytes(src []byte) []byte {
    *i = Int16(int16(hostarch.ByteOrder.Uint16(src[:2])))
    return src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Int16) Packed() bool {
    return true
}

func (i *Int16) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *Int16) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *Int16) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int16) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *Int16) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int16) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *Int16) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *Int16) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:], true
}

func (i *Int16) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyInt16SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []int16) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Int16)(nil).SizeBytes()

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

func CopyInt16SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []int16) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Int16)(nil).SizeBytes()

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

func MarshalUnsafeInt16Slice(src []Int16, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Int16)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeInt16Slice(dst []Int16, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Int16)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Int32) SizeBytes() int {
    return 4
}

func (i *Int32) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*i))
    return dst[4:]
}

func (i *Int32) UnmarshalBytes(src []byte) []byte {
    *i = Int32(int32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Int32) Packed() bool {
    return true
}

func (i *Int32) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *Int32) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *Int32) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int32) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *Int32) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int32) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *Int32) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *Int32) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:], true
}

func (i *Int32) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyInt32SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []int32) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Int32)(nil).SizeBytes()

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

func CopyInt32SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []int32) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Int32)(nil).SizeBytes()

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

func MarshalUnsafeInt32Slice(src []Int32, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Int32)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeInt32Slice(dst []Int32, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Int32)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Int64) SizeBytes() int {
    return 8
}

func (i *Int64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*i))
    return dst[8:]
}

func (i *Int64) UnmarshalBytes(src []byte) []byte {
    *i = Int64(int64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Int64) Packed() bool {
    return true
}

func (i *Int64) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *Int64) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *Int64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *Int64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *Int64) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *Int64) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:], true
}

func (i *Int64) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyInt64SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []int64) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Int64)(nil).SizeBytes()

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

func CopyInt64SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []int64) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Int64)(nil).SizeBytes()

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

func MarshalUnsafeInt64Slice(src []Int64, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Int64)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeInt64Slice(dst []Int64, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Int64)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (i *Int8) SizeBytes() int {
    return 1
}

func (i *Int8) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(*i)
    return dst[1:]
}

func (i *Int8) UnmarshalBytes(src []byte) []byte {
    *i = Int8(int8(src[0]))
    return src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (i *Int8) Packed() bool {
    return true
}

func (i *Int8) MarshalUnsafe(dst []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:]
}

func (i *Int8) UnmarshalUnsafe(src []byte) []byte {
    size := i.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (i *Int8) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int8) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyOutN(cc, addr, i.SizeBytes())
}

func (i *Int8) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(i)
    return length, err
}

func (i *Int8) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return i.CopyInN(cc, addr, i.SizeBytes())
}

func (i *Int8) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(i)))
    hdr.Len = i.SizeBytes()
    hdr.Cap = i.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(i)
    return int64(length), err
}

func (i *Int8) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(i), uintptr(size))
    return dst[size:], true
}

func (i *Int8) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := i.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(i), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyInt8SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []int8) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Int8)(nil).SizeBytes()

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

func CopyInt8SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []int8) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Int8)(nil).SizeBytes()

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

func MarshalUnsafeInt8Slice(src []Int8, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Int8)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeInt8Slice(dst []Int8, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Int8)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (u *Uint16) SizeBytes() int {
    return 2
}

func (u *Uint16) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint16(dst[:2], uint16(*u))
    return dst[2:]
}

func (u *Uint16) UnmarshalBytes(src []byte) []byte {
    *u = Uint16(uint16(hostarch.ByteOrder.Uint16(src[:2])))
    return src[2:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Uint16) Packed() bool {
    return true
}

func (u *Uint16) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

func (u *Uint16) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (u *Uint16) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint16) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *Uint16) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint16) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *Uint16) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

func (u *Uint16) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:], true
}

func (u *Uint16) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyUint16SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []uint16) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint16)(nil).SizeBytes()

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

func CopyUint16SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []uint16) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint16)(nil).SizeBytes()

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

func MarshalUnsafeUint16Slice(src []Uint16, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Uint16)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeUint16Slice(dst []Uint16, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Uint16)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (u *Uint32) SizeBytes() int {
    return 4
}

func (u *Uint32) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint32(dst[:4], uint32(*u))
    return dst[4:]
}

func (u *Uint32) UnmarshalBytes(src []byte) []byte {
    *u = Uint32(uint32(hostarch.ByteOrder.Uint32(src[:4])))
    return src[4:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Uint32) Packed() bool {
    return true
}

func (u *Uint32) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

func (u *Uint32) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (u *Uint32) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint32) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *Uint32) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint32) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *Uint32) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

func (u *Uint32) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:], true
}

func (u *Uint32) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyUint32SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []uint32) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint32)(nil).SizeBytes()

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

func CopyUint32SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []uint32) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint32)(nil).SizeBytes()

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

func MarshalUnsafeUint32Slice(src []Uint32, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Uint32)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeUint32Slice(dst []Uint32, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Uint32)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (u *Uint64) SizeBytes() int {
    return 8
}

func (u *Uint64) MarshalBytes(dst []byte) []byte {
    hostarch.ByteOrder.PutUint64(dst[:8], uint64(*u))
    return dst[8:]
}

func (u *Uint64) UnmarshalBytes(src []byte) []byte {
    *u = Uint64(uint64(hostarch.ByteOrder.Uint64(src[:8])))
    return src[8:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Uint64) Packed() bool {
    return true
}

func (u *Uint64) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

func (u *Uint64) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (u *Uint64) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint64) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *Uint64) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint64) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *Uint64) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

func (u *Uint64) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:], true
}

func (u *Uint64) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyUint64SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []uint64) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint64)(nil).SizeBytes()

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

func CopyUint64SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []uint64) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint64)(nil).SizeBytes()

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

func MarshalUnsafeUint64Slice(src []Uint64, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Uint64)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeUint64Slice(dst []Uint64, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Uint64)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
//go:nosplit
func (u *Uint8) SizeBytes() int {
    return 1
}

func (u *Uint8) MarshalBytes(dst []byte) []byte {
    dst[0] = byte(*u)
    return dst[1:]
}

func (u *Uint8) UnmarshalBytes(src []byte) []byte {
    *u = Uint8(uint8(src[0]))
    return src[1:]
}

// Packed implements marshal.Marshallable.Packed.
//go:nosplit
func (u *Uint8) Packed() bool {
    return true
}

func (u *Uint8) MarshalUnsafe(dst []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:]
}

func (u *Uint8) UnmarshalUnsafe(src []byte) []byte {
    size := u.SizeBytes()
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:]
}

func (u *Uint8) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyOutBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint8) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyOutN(cc, addr, u.SizeBytes())
}

func (u *Uint8) CopyInN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := cc.CopyInBytes(addr, buf[:limit])
    runtime.KeepAlive(u)
    return length, err
}

func (u *Uint8) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
    return u.CopyInN(cc, addr, u.SizeBytes())
}

func (u *Uint8) WriteTo(writer io.Writer) (int64, error) {
    var buf []byte
    hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
    hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(u)))
    hdr.Len = u.SizeBytes()
    hdr.Cap = u.SizeBytes()

    length, err := writer.Write(buf)
    runtime.KeepAlive(u)
    return int64(length), err
}

func (u *Uint8) CheckedMarshal(dst []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(dst) {
        return dst, false
    }
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(u), uintptr(size))
    return dst[size:], true
}

func (u *Uint8) CheckedUnmarshal(src []byte) ([]byte, bool) {
    size := u.SizeBytes()
    if size > len(src) {
        return src, false
    }
    gohacks.Memmove(unsafe.Pointer(u), unsafe.Pointer(&src[0]), uintptr(size))
    return src[size:], true
}

func CopyUint8SliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst []uint8) (int, error) {
    count := len(dst)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint8)(nil).SizeBytes()

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

func CopyUint8SliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []uint8) (int, error) {
    count := len(src)
    if count == 0 {
        return 0, nil
    }
    size := (*Uint8)(nil).SizeBytes()

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

func MarshalUnsafeUint8Slice(src []Uint8, dst []byte) []byte {
    count := len(src)
    if count == 0 {
        return dst
    }
    size := (*Uint8)(nil).SizeBytes()

    buf := dst[:size*count]
    gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))
    return dst[size*count:]
}

func UnmarshalUnsafeUint8Slice(dst []Uint8, src []byte) []byte {
    count := len(dst)
    if count == 0 {
        return src
    }
    size := (*Uint8)(nil).SizeBytes()

    buf := src[:size*count]
    gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))
    return src[size*count:]
}

