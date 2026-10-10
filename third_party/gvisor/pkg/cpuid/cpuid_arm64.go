// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package cpuid

import (
	"fmt"
	"io"
)

type FeatureSet struct {
	hwCap      hwCap
	cpuFreqMHz float64
	cpuImplHex uint64
	cpuArchDec uint64
	cpuVarHex  uint64
	cpuPartHex uint64
	cpuRevDec  uint64
}

func (fs FeatureSet) CPUImplementer() uint8 {
	return uint8(fs.cpuImplHex)
}

func (fs FeatureSet) CPUArchitecture() uint8 {
	return uint8(fs.cpuArchDec)
}

func (fs FeatureSet) CPUVariant() uint8 {
	return uint8(fs.cpuVarHex)
}

func (fs FeatureSet) CPUPartnum() uint16 {
	return uint16(fs.cpuPartHex)
}

func (fs FeatureSet) CPURevision() uint8 {
	return uint8(fs.cpuRevDec)
}

func (fs FeatureSet) ExtendedStateSize() (size, align uint) {
	return 528, 16
}

func (fs FeatureSet) HasFeature(feature Feature) bool {
	return fs.hwCap.hwCap1&(1<<feature) != 0
}

func (fs FeatureSet) WriteCPUInfoTo(cpu, numCPU uint, w io.Writer) {
	fmt.Fprintf(w, "processor\t: %d\n", cpu)
	fmt.Fprintf(w, "BogoMIPS\t: %.02f\n", fs.cpuFreqMHz)
	fmt.Fprintf(w, "Features\t\t: %s\n", fs.FlagString())
	fmt.Fprintf(w, "CPU implementer\t: 0x%x\n", fs.cpuImplHex)
	fmt.Fprintf(w, "CPU architecture\t: %d\n", fs.cpuArchDec)
	fmt.Fprintf(w, "CPU variant\t: 0x%x\n", fs.cpuVarHex)
	fmt.Fprintf(w, "CPU part\t: 0x%x\n", fs.cpuPartHex)
	fmt.Fprintf(w, "CPU revision\t: %d\n", fs.cpuRevDec)
	fmt.Fprintf(w, "\n")
}

func (FeatureSet) archCheckHostCompatible(FeatureSet) error {
	return nil
}

func (fs FeatureSet) AllowedHWCap1() uint64 {
	allowed := HWCAP_AES |
		HWCAP_ASIMD |
		HWCAP_ASIMDDP |
		HWCAP_ASIMDFHM |
		HWCAP_ASIMDHP |
		HWCAP_ASIMDRDM |
		HWCAP_ATOMICS |
		HWCAP_CRC32 |
		HWCAP_DCPOP |
		HWCAP_DIT |
		HWCAP_EVTSTRM |
		HWCAP_FCMA |
		HWCAP_FLAGM |
		HWCAP_FP |
		HWCAP_FPHP |
		HWCAP_ILRCPC |
		HWCAP_JSCVT |
		HWCAP_LRCPC |
		HWCAP_PMULL |
		HWCAP_SHA1 |
		HWCAP_SHA2 |
		HWCAP_SHA3 |
		HWCAP_SHA512 |
		HWCAP_SM3 |
		HWCAP_SM4 |
		HWCAP_USCAT
	return fs.hwCap.hwCap1 & uint64(allowed)
}

func (fs FeatureSet) AllowedHWCap2() uint64 {
	allowed := 0
	return fs.hwCap.hwCap2 & uint64(allowed)
}
