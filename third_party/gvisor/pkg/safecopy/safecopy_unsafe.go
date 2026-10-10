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

package safecopy

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const maxRegisterSize = 16

// memcpy copies data from src to dst. If a SIGSEGV or SIGBUS signal is received
// during the copy, it returns the address that caused the fault and the number
// of the signal that was received. Otherwise, it returns an unspecified address
// and a signal number of 0.
//
// Data is copied in order, such that if a fault happens at address p, it is
// safe to assume that all data before p-maxRegisterSize has already been
// successfully copied.
//
//go:noescape
func memcpy(dst, src uintptr, n uintptr) (fault uintptr, sig int32)

// memclr sets the n bytes following ptr to zeroes. If a SIGSEGV or SIGBUS
// signal is received during the write, it returns the address that caused the
// fault and the number of the signal that was received. Otherwise, it returns
// an unspecified address and a signal number of 0.
//
// Data is written in order, such that if a fault happens at address p, it is
// safe to assume that all data before p-maxRegisterSize has already been
// successfully written.
//
//go:noescape
func memclr(ptr uintptr, n uintptr) (fault uintptr, sig int32)

// swapUint32 atomically stores new into *ptr and returns (the previous *ptr
// value, 0). If a SIGSEGV or SIGBUS signal is received during the swap, the
// value of old is unspecified, and sig is the number of the signal that was
// received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//go:noescape
func swapUint32(ptr unsafe.Pointer, new uint32) (old uint32, sig int32)

// swapUint64 atomically stores new into *ptr and returns (the previous *ptr
// value, 0). If a SIGSEGV or SIGBUS signal is received during the swap, the
// value of old is unspecified, and sig is the number of the signal that was
// received.
//
// Preconditions: ptr must be aligned to a 8-byte boundary.
//
//go:noescape
func swapUint64(ptr unsafe.Pointer, new uint64) (old uint64, sig int32)

// compareAndSwapUint32 is like sync/atomic.CompareAndSwapUint32, but returns
// (the value previously stored at ptr, 0). If a SIGSEGV or SIGBUS signal is
// received during the operation, the value of prev is unspecified, and sig is
// the number of the signal that was received.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//go:noescape
func compareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (prev uint32, sig int32)

// LoadUint32 is like sync/atomic.LoadUint32, but operates with user memory. It
// may fail with SIGSEGV or SIGBUS if it is received while reading from ptr.
//
// Preconditions: ptr must be aligned to a 4-byte boundary.
//
//go:noescape
func loadUint32(ptr unsafe.Pointer) (val uint32, sig int32)

func addrOfMemcpy() uintptr
func addrOfMemclr() uintptr
func addrOfSwapUint32() uintptr
func addrOfSwapUint64() uintptr
func addrOfCompareAndSwapUint32() uintptr
func addrOfLoadUint32() uintptr

func CopyIn(dst []byte, src unsafe.Pointer) (int, error) {
	n, err := copyIn(dst, uintptr(src))
	runtime.KeepAlive(src)
	return n, err
}

func copyIn(dst []byte, src uintptr) (int, error) {
	toCopy := uintptr(len(dst))
	if len(dst) == 0 {
		return 0, nil
	}

	fault, sig := memcpy(uintptr(unsafe.Pointer(&dst[0])), src, toCopy)
	if sig == 0 {
		return len(dst), nil
	}

	if fault < src || fault >= src+toCopy {
		panic(fmt.Sprintf("CopyIn raised signal %d at %#x, which is outside source [%#x, %#x)", sig, fault, src, src+toCopy))
	}

	var done int
	if fault-src > maxRegisterSize {
		done = int(fault - src - maxRegisterSize)
	}
	n, err := copyIn(dst[done:int(fault-src)], src+uintptr(done))
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

func CopyOut(dst unsafe.Pointer, src []byte) (int, error) {
	n, err := copyOut(uintptr(dst), src)
	runtime.KeepAlive(dst)
	return n, err
}

func copyOut(dst uintptr, src []byte) (int, error) {
	toCopy := uintptr(len(src))
	if toCopy == 0 {
		return 0, nil
	}

	fault, sig := memcpy(dst, uintptr(unsafe.Pointer(&src[0])), toCopy)
	if sig == 0 {
		return len(src), nil
	}

	if fault < dst || fault >= dst+toCopy {
		panic(fmt.Sprintf("CopyOut raised signal %d at %#x, which is outside destination [%#x, %#x)", sig, fault, dst, dst+toCopy))
	}

	var done int
	if fault-dst > maxRegisterSize {
		done = int(fault - dst - maxRegisterSize)
	}
	n, err := copyOut(dst+uintptr(done), src[done:int(fault-dst)])
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

func Copy(dst, src unsafe.Pointer, toCopy uintptr) (uintptr, error) {
	n, err := copyN(uintptr(dst), uintptr(src), toCopy)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(src)
	return n, err
}

func copyN(dst, src uintptr, toCopy uintptr) (uintptr, error) {
	if toCopy == 0 {
		return 0, nil
	}

	fault, sig := memcpy(dst, src, toCopy)
	if sig == 0 {
		return toCopy, nil
	}

	faultAfterSrc := ^uintptr(0)
	if fault >= src {
		faultAfterSrc = fault - src
	}
	faultAfterDst := ^uintptr(0)
	if fault >= dst {
		faultAfterDst = fault - dst
	}
	if faultAfterSrc >= toCopy && faultAfterDst >= toCopy {
		panic(fmt.Sprintf("Copy raised signal %d at %#x, which is outside source [%#x, %#x) and destination [%#x, %#x)", sig, fault, src, src+toCopy, dst, dst+toCopy))
	}
	faultedAfter := faultAfterSrc
	if faultedAfter > faultAfterDst {
		faultedAfter = faultAfterDst
	}

	var done uintptr
	if faultedAfter > maxRegisterSize {
		done = faultedAfter - maxRegisterSize
	}
	n, err := copyN(dst+done, src+done, faultedAfter-done)
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

func ZeroOut(dst unsafe.Pointer, toZero uintptr) (uintptr, error) {
	n, err := zeroOut(uintptr(dst), toZero)
	runtime.KeepAlive(dst)
	return n, err
}

func zeroOut(dst uintptr, toZero uintptr) (uintptr, error) {
	if toZero == 0 {
		return 0, nil
	}

	fault, sig := memclr(dst, toZero)
	if sig == 0 {
		return toZero, nil
	}

	if fault < dst || fault >= dst+toZero {
		panic(fmt.Sprintf("ZeroOut raised signal %d at %#x, which is outside destination [%#x, %#x)", sig, fault, dst, dst+toZero))
	}

	var done uintptr
	if fault-dst > maxRegisterSize {
		done = fault - dst - maxRegisterSize
	}
	n, err := zeroOut(dst+done, fault-dst-done)
	done += n
	if err != nil {
		return done, err
	}
	return done, errorFromFaultSignal(fault, sig)
}

func SwapUint32(ptr unsafe.Pointer, new uint32) (uint32, error) {
	if addr := uintptr(ptr); addr&3 != 0 {
		return 0, AlignmentError{addr, 4}
	}
	old, sig := swapUint32(ptr, new)
	return old, errorFromFaultSignal(uintptr(ptr), sig)
}

func SwapUint64(ptr unsafe.Pointer, new uint64) (uint64, error) {
	if addr := uintptr(ptr); addr&7 != 0 {
		return 0, AlignmentError{addr, 8}
	}
	old, sig := swapUint64(ptr, new)
	return old, errorFromFaultSignal(uintptr(ptr), sig)
}

func CompareAndSwapUint32(ptr unsafe.Pointer, old, new uint32) (uint32, error) {
	if addr := uintptr(ptr); addr&3 != 0 {
		return 0, AlignmentError{addr, 4}
	}
	prev, sig := compareAndSwapUint32(ptr, old, new)
	return prev, errorFromFaultSignal(uintptr(ptr), sig)
}

func LoadUint32(ptr unsafe.Pointer) (uint32, error) {
	if addr := uintptr(ptr); addr&3 != 0 {
		return 0, AlignmentError{addr, 4}
	}
	val, sig := loadUint32(ptr)
	return val, errorFromFaultSignal(uintptr(ptr), sig)
}

func errorFromFaultSignal(addr uintptr, sig int32) error {
	switch sig {
	case 0:
		return nil
	case int32(unix.SIGSEGV):
		return SegvError{addr}
	case int32(unix.SIGBUS):
		return BusError{addr}
	default:
		panic(fmt.Sprintf("safecopy got unexpected signal %d at address %#x", sig, addr))
	}
}
