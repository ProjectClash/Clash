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
	"bufio"
	"bytes"
	"os"
	"strconv"

	"github.com/metacubex/gvisor/pkg/log"
)

type cpuidFunction uint64

func (f cpuidFunction) eax() uint32 {
	return uint32(f)
}

func (f cpuidFunction) ecx() uint32 {
	return uint32(f >> 32)
}

const (
	vendorID                      cpuidFunction = 0x0
	featureInfo                   cpuidFunction = 0x1
	intelCacheDescriptors         cpuidFunction = 0x2
	intelSerialNumber             cpuidFunction = 0x3
	intelDeterministicCacheParams cpuidFunction = 0x4
	monitorMwaitParams            cpuidFunction = 0x5
	powerParams                   cpuidFunction = 0x6
	extendedFeatureInfo           cpuidFunction = 0x7
	_
	intelDCAParams                cpuidFunction = 0x9
	intelPMCInfo                  cpuidFunction = 0xa
	intelX2APICInfo               cpuidFunction = 0xb
	_
	xSaveInfo                     cpuidFunction = 0xd
	xSaveInfoSub                  cpuidFunction = 0xd | (0x1 << 32)
)

const xSaveInfoNumLeaves = 64

const (
	extendedStart           cpuidFunction = 0x80000000
	extendedFunctionInfo    cpuidFunction = extendedStart + 0
	extendedFeatures                      = extendedStart + 1
	processorBrandString2                 = extendedStart + 2
	processorBrandString3                 = extendedStart + 3
	processorBrandString4                 = extendedStart + 4
	l1CacheAndTLBInfo                     = extendedStart + 5
	l2CacheInfo                           = extendedStart + 6
	addressSizes                          = extendedStart + 8
	amdMemoryEncryptionInfo               = extendedStart + 31
)

const (
	amdSecureMemoryEncryption        = 1 << 0
	amdSecureEncryptedVirtualization = 1 << 1
	amdMemoryEncryptionFeatureMask   = amdSecureMemoryEncryption | amdSecureEncryptedVirtualization
	amdPhysAddrReductionShift        = 6
	amdPhysAddrReductionMask         = 0x3f
)

var allowedBasicFunctions = [...]bool{
	vendorID:                      true,
	featureInfo:                   true,
	extendedFeatureInfo:           true,
	intelCacheDescriptors:         true,
	intelDeterministicCacheParams: true,
	xSaveInfo:                     true,
}

var allowedExtendedFunctions = [...]bool{
	extendedFunctionInfo - extendedStart:    true,
	extendedFeatures - extendedStart:        true,
	addressSizes - extendedStart:            true,
	processorBrandString2 - extendedStart:   true,
	processorBrandString3 - extendedStart:   true,
	processorBrandString4 - extendedStart:   true,
	l1CacheAndTLBInfo - extendedStart:       true,
	l2CacheInfo - extendedStart:             true,
	amdMemoryEncryptionInfo - extendedStart: true,
}

type Function interface {
	Query(In) Out
}

type Native struct{}

type In struct {
	Eax uint32
	Ecx uint32
}

func (i *In) normalize() {
	switch cpuidFunction(i.Eax) {
	case vendorID, featureInfo, intelCacheDescriptors, extendedFunctionInfo, extendedFeatures:
		i.Ecx = 0
	case processorBrandString2, processorBrandString3, processorBrandString4, l1CacheAndTLBInfo, l2CacheInfo, amdMemoryEncryptionInfo:
		i.Ecx = 0
	case intelDeterministicCacheParams, extendedFeatureInfo:
	}
}

type Out struct {
	Eax uint32
	Ebx uint32
	Ecx uint32
	Edx uint32
}

func native(In) Out

// Query executes CPUID natively.
//
// This implements Function.
//
//go:nosplit
func (*Native) Query(in In) Out {
	if int(in.Eax) < len(allowedBasicFunctions) && allowedBasicFunctions[in.Eax] {
		return native(in)
	} else if in.Eax >= uint32(extendedStart) {
		if l := int(in.Eax - uint32(extendedStart)); l < len(allowedExtendedFunctions) && allowedExtendedFunctions[l] {
			return native(in)
		}
	}
	return Out{}
}

// query is a internal wrapper.
//
//go:nosplit
func (fs FeatureSet) query(fn cpuidFunction) (uint32, uint32, uint32, uint32) {
	out := fs.Query(In{Eax: fn.eax(), Ecx: fn.ecx()})
	return out.Eax, out.Ebx, out.Ecx, out.Edx
}

func (fs FeatureSet) Intersect(allowedFeatures map[Feature]struct{}) (FeatureSet, error) {
	hs := fs.ToStatic()

	for f := range allFeatures {
		if fs.HasFeature(f) {
			if _, ok := allowedFeatures[f]; !ok {
				log.Infof("Removing CPU feature %v as it is not allowed.", f)
				hs.Remove(f)
			}
		}
	}

	return hs.ToFeatureSet(), nil
}

var hostFeatureSet FeatureSet

// HostFeatureSet returns a host CPUID.
//
//go:nosplit
func HostFeatureSet() FeatureSet {
	return hostFeatureSet
}

var (
	cpuFreqMHz float64
)

func readMaxCPUFreq() {
	cpuinfoFile, err := os.Open("/proc/cpuinfo")
	if err != nil {
		log.Warningf("Could not open /proc/cpuinfo: %v", err)
		return
	}
	defer cpuinfoFile.Close()

	s := bufio.NewScanner(cpuinfoFile)
	for s.Scan() {
		line := s.Bytes()
		if bytes.Contains(line, []byte("cpu MHz")) {
			splitMHz := bytes.Split(line, []byte(":"))
			if len(splitMHz) < 2 {
				log.Warningf("Could not parse /proc/cpuinfo: malformed cpu MHz line: %q", line)
				return
			}

			var err error
			splitMHzStr := string(bytes.TrimSpace(splitMHz[1]))
			f64MHz, err := strconv.ParseFloat(splitMHzStr, 64)
			if err != nil {
				log.Warningf("Could not parse cpu MHz value %q: %v", splitMHzStr, err)
				return
			}
			cpuFreqMHz = f64MHz
			return
		}
	}
	if err := s.Err(); err != nil {
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	log.Warningf("Could not parse /proc/cpuinfo, it is empty or does not contain cpu MHz")
}

func xgetbv(reg uintptr) uint64

func archInitialize() {
	hostFeatureSet = FeatureSet{
		Function: &Native{},
	}.Fixed()

	readMaxCPUFreq()
	initHWCap()
}
