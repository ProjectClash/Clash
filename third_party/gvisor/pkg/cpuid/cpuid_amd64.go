// Copyright 2019 The gVisor Authors.
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

//go:build amd64
// +build amd64

package cpuid

import (
	"context"
	"fmt"
	"io"
)

type FeatureSet struct {
	Function `state:".(Static)"`
	hwCap hwCap
}

func (fs *FeatureSet) saveFunction() Static {
	if s, ok := fs.Function.(Static); ok {
		return s
	}
	return fs.ToStatic()
}

func (fs *FeatureSet) loadFunction(_ context.Context, s Static) {
	fs.Function = s
}

// Helper to convert 3 regs into 12-byte vendor ID.
//
//go:nosplit
func vendorIDFromRegs(bx, cx, dx uint32) (r [12]byte) {
	for i := uint(0); i < 4; i++ {
		b := byte(bx >> (i * 8))
		r[i] = b
	}

	for i := uint(0); i < 4; i++ {
		b := byte(dx >> (i * 8))
		r[4+i] = b
	}

	for i := uint(0); i < 4; i++ {
		b := byte(cx >> (i * 8))
		r[8+i] = b
	}

	return r
}

func regsFromVendorID(r [12]byte) (bx, cx, dx uint32) {
	bx |= uint32(r[0])
	bx |= uint32(r[1]) << 8
	bx |= uint32(r[2]) << 16
	bx |= uint32(r[3]) << 24
	cx |= uint32(r[4])
	cx |= uint32(r[5]) << 8
	cx |= uint32(r[6]) << 16
	cx |= uint32(r[7]) << 24
	dx |= uint32(r[8])
	dx |= uint32(r[9]) << 8
	dx |= uint32(r[10]) << 16
	dx |= uint32(r[10]) << 24
	return
}

// VendorID is the 12-char string returned in ebx:edx:ecx for eax=0.
//
//go:nosplit
func (fs FeatureSet) VendorID() [12]byte {
	_, bx, cx, dx := fs.query(vendorID)
	return vendorIDFromRegs(bx, cx, dx)
}

// Helper to deconstruct signature dword.
//
//go:nosplit
func signatureSplit(v uint32) (ef, em, pt, f, m, sid uint8) {
	sid = uint8(v & 0xf)
	m = uint8(v>>4) & 0xf
	f = uint8(v>>8) & 0xf
	pt = uint8(v>>12) & 0x3
	em = uint8(v>>16) & 0xf
	ef = uint8(v >> 20)
	return
}

// ExtendedFamily is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) ExtendedFamily() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	ef, _, _, _, _, _ := signatureSplit(ax)
	return ef
}

// ExtendedModel is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) ExtendedModel() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, em, _, _, _, _ := signatureSplit(ax)
	return em
}

// ProcessorType is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) ProcessorType() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, pt, _, _, _ := signatureSplit(ax)
	return pt
}

// Family is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) Family() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, _, f, _, _ := signatureSplit(ax)
	return f
}

// Model is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) Model() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, _, _, m, _ := signatureSplit(ax)
	return m
}

// SteppingID is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) SteppingID() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, _, _, _, sid := signatureSplit(ax)
	return sid
}

// VirtualAddressBits returns the number of bits available for virtual
// addresses.
//
//go:nosplit
func (fs FeatureSet) VirtualAddressBits() uint32 {
	ax, _, _, _ := fs.query(addressSizes)
	return (ax >> 8) & 0xff
}

// PhysicalAddressBits returns the number of bits available for physical
// addresses.
//
//go:nosplit
func (fs FeatureSet) PhysicalAddressBits() uint32 {
	ax, _, _, _ := fs.query(addressSizes)
	physBits := ax & 0xff
	if !fs.AMD() {
		return physBits
	}

	maxExtended, _, _, _ := fs.query(extendedFunctionInfo)
	if maxExtended < uint32(amdMemoryEncryptionInfo) {
		return physBits
	}

	memEncAX, memEncBX, _, _ := fs.query(amdMemoryEncryptionInfo)
	if memEncAX&amdMemoryEncryptionFeatureMask == 0 {
		return physBits
	}
	return physBits - ((memEncBX >> amdPhysAddrReductionShift) & amdPhysAddrReductionMask)
}

type CacheType uint8

const (
	cacheNull CacheType = iota

	CacheData

	CacheInstruction

	CacheUnified
)

type Cache struct {
	Level uint32

	Type CacheType

	FullyAssociative bool

	Partitions uint32

	Ways uint32

	Sets uint32

	InvalidateHierarchical bool

	Inclusive bool

	DirectMapped bool
}

func (fs FeatureSet) Caches() (caches []Cache) {
	if !fs.Intel() {
		return
	}
	cacheLine := fs.CacheLine()
	for i := uint32(0); ; i++ {
		out := fs.Query(In{
			Eax: uint32(intelDeterministicCacheParams),
			Ecx: i,
		})
		t := CacheType(out.Eax & 0xf)
		if t == cacheNull {
			break
		}
		lineSize := (out.Ebx & 0xfff) + 1
		if lineSize != cacheLine {
			panic(fmt.Sprintf("Mismatched cache line size: %d vs %d", lineSize, cacheLine))
		}
		caches = append(caches, Cache{
			Type:                   t,
			Level:                  (out.Eax >> 5) & 0x7,
			FullyAssociative:       ((out.Eax >> 9) & 1) == 1,
			Partitions:             ((out.Ebx >> 12) & 0x3ff) + 1,
			Ways:                   ((out.Ebx >> 22) & 0x3ff) + 1,
			Sets:                   out.Ecx + 1,
			InvalidateHierarchical: (out.Edx & 1) == 0,
			Inclusive:              ((out.Edx >> 1) & 1) == 1,
			DirectMapped:           ((out.Edx >> 2) & 1) == 0,
		})
	}
	return
}

// CacheLine is the size of a cache line in bytes.
//
// All caches use the same line size. This is not enforced in the CPUID
// encoding, but is true on all known x86 processors.
//
//go:nosplit
func (fs FeatureSet) CacheLine() uint32 {
	_, bx, _, _ := fs.query(featureInfo)
	return 8 * (bx >> 8) & 0xff
}

// HasFeature tests whether or not a feature is in the given feature set.
//
// This function is safe to call from a nosplit context, as long as the
// FeatureSet does not have any masked features.
//
//go:nosplit
func (fs FeatureSet) HasFeature(feature Feature) bool {
	return feature.check(fs)
}

func (fs FeatureSet) WriteCPUInfoTo(cpu, numCPU uint, w io.Writer) {
	ax, _, _, _ := fs.query(featureInfo)
	ef, em, _, f, m, _ := signatureSplit(ax)
	vendor := fs.VendorID()
	fmt.Fprintf(w, "processor\t: %d\n", cpu)
	fmt.Fprintf(w, "vendor_id\t: %s\n", string(vendor[:]))
	fmt.Fprintf(w, "cpu family\t: %d\n", ((ef<<4)&0xff)|f)
	fmt.Fprintf(w, "model\t\t: %d\n", ((em<<4)&0xff)|m)
	fmt.Fprintf(w, "model name\t: %s\n", "unknown")
	fmt.Fprintf(w, "stepping\t: %s\n", "unknown")
	fmt.Fprintf(w, "cpu MHz\t\t: %.3f\n", cpuFreqMHz)
	fmt.Fprintf(w, "cache size\t: 8192 KB\n")
	fmt.Fprintf(w, "physical id\t: 0\n")
	fmt.Fprintf(w, "siblings\t: %d\n", numCPU)
	fmt.Fprintf(w, "core id\t\t: %d\n", cpu)
	fmt.Fprintf(w, "cpu cores\t: %d\n", numCPU)
	fmt.Fprintf(w, "apicid\t\t: %d\n", cpu)
	fmt.Fprintf(w, "initial apicid\t: %d\n", cpu)
	fmt.Fprintf(w, "fpu\t\t: yes\n")
	fmt.Fprintf(w, "fpu_exception\t: yes\n")
	fmt.Fprintf(w, "cpuid level\t: %d\n", uint32(xSaveInfo))
	fmt.Fprintf(w, "wp\t\t: yes\n")
	fmt.Fprintf(w, "flags\t\t: %s\n", fs.FlagString())
	fmt.Fprintf(w, "bogomips\t: %.02f\n", cpuFreqMHz)
	fmt.Fprintf(w, "clflush size\t: %d\n", fs.CacheLine())
	fmt.Fprintf(w, "cache_alignment\t: %d\n", fs.CacheLine())
	fmt.Fprintf(w, "address sizes\t: %d bits physical, %d bits virtual\n", 46, 48)
	fmt.Fprintf(w, "power management:\n")
	fmt.Fprintf(w, "\n")
}

var (
	authenticAMD = [12]byte{'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'A', 'M', 'D'}
	genuineIntel = [12]byte{'G', 'e', 'n', 'u', 'i', 'n', 'e', 'I', 'n', 't', 'e', 'l'}
)

// AMD returns true if fs describes an AMD CPU.
//
//go:nosplit
func (fs FeatureSet) AMD() bool {
	return fs.VendorID() == authenticAMD
}

// Intel returns true if fs describes an Intel CPU.
//
//go:nosplit
func (fs FeatureSet) Intel() bool {
	return fs.VendorID() == genuineIntel
}

var (
	xsaveSize       = native(In{Eax: uint32(xSaveInfo)}).Ebx
	maxXsaveSize    = native(In{Eax: uint32(xSaveInfo)}).Ecx
	amxTileCfgSize  = native(In{Eax: uint32(xSaveInfo), Ecx: 17}).Eax
	amxTileDataSize = native(In{Eax: uint32(xSaveInfo), Ecx: 18}).Eax
)

const (
	XCR0AmxCfgMask = uint64(1 << 17)

	XCR0AmxDataMask = uint64(1 << 18)
)

// ExtendedStateSize returns the number of bytes needed to save the "extended
// state" for the enabled features and the boundary it must be aligned to.
// Extended state includes floating point registers, and other cpu state that's
// not associated with the normal task context.
//
// Note: the return value matches the size of signal FP state frames.
// Look at check_xstate_in_sigframe() in the kernel sources for more details.
//
//go:nosplit
func (fs FeatureSet) ExtendedStateSize() (size, align uint) {
	if fs.UseXsave() {
		return uint(xsaveSize), 64
	}

	return 512, 16
}

func (fs FeatureSet) AMXExtendedStateSize() uint {
	total := uint(0)
	if fs.UseXsave() {
		xcr0 := xgetbv(0)
		if (xcr0 & XCR0AmxDataMask) != 0 {
			total += uint(amxTileDataSize)
		}
	}
	return total
}

// ValidXCR0Mask returns the valid bits in control register XCR0.
//
// Always exclude AMX bits, because we do not support it.
// TODO(gvisor.dev/issues/9896): Implement AMX Support.
//
//go:nosplit
func (fs FeatureSet) ValidXCR0Mask() uint64 {
	if !fs.HasFeature(X86FeatureXSAVE) {
		return 0
	}
	ax, _, _, dx := fs.query(xSaveInfo)
	return (uint64(dx)<<32 | uint64(ax)) &^ (XCR0AmxCfgMask | XCR0AmxDataMask)
}

// UseXsave returns the choice of fp state saving instruction.
//
//go:nosplit
func (fs FeatureSet) UseXsave() bool {
	return fs.HasFeature(X86FeatureXSAVE) && fs.HasFeature(X86FeatureOSXSAVE)
}

// UseXsaveopt returns true if 'fs' supports the "xsaveopt" instruction.
//
//go:nosplit
func (fs FeatureSet) UseXsaveopt() bool {
	return fs.UseXsave() && fs.HasFeature(X86FeatureXSAVEOPT)
}

// UseXsavec returns true if 'fs' supports the "xsavec" instruction.
//
//go:nosplit
func (fs FeatureSet) UseXsavec() bool {
	return fs.UseXsaveopt() && fs.HasFeature(X86FeatureXSAVEC)
}

func (fs FeatureSet) UseFSGSBASE() bool {
	HWCAP2_FSGSBASE := uint64(1) << 1
	return fs.HasFeature(X86FeatureFSGSBase) && ((fs.hwCap.hwCap2 & HWCAP2_FSGSBASE) != 0)
}

func (fs FeatureSet) archCheckHostCompatible(hfs FeatureSet) error {
	fsCache := fs.CacheLine()
	hostCache := hfs.CacheLine()
	if fsCache != hostCache {
		return &ErrIncompatible{
			reason: fmt.Sprintf("CPU cache line size %d incompatible with host cache line size %d", fsCache, hostCache),
		}
	}

	return nil
}

func (fs FeatureSet) AllowedHWCap1() uint64 {
	return 0
}

func (fs FeatureSet) AllowedHWCap2() uint64 {
	return 0
}
