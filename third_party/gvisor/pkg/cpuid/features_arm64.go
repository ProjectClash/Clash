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

const (
	ARM64FeatureFP Feature = iota

	ARM64FeatureASIMD

	ARM64FeatureEVTSTRM

	ARM64FeatureAES

	ARM64FeaturePMULL

	ARM64FeatureSHA1

	ARM64FeatureSHA2

	ARM64FeatureCRC32

	ARM64FeatureATOMICS

	ARM64FeatureFPHP

	ARM64FeatureASIMDHP

	ARM64FeatureCPUID

	ARM64FeatureASIMDRDM

	ARM64FeatureJSCVT

	ARM64FeatureFCMA

	ARM64FeatureLRCPC

	ARM64FeatureDCPOP

	ARM64FeatureSHA3

	ARM64FeatureSM3

	ARM64FeatureSM4

	ARM64FeatureASIMDDP

	ARM64FeatureSHA512

	ARM64FeatureSVE

	ARM64FeatureASIMDFHM
)

var allFeatures = map[Feature]allFeatureInfo{
	ARM64FeatureFP:       {"fp", true},
	ARM64FeatureASIMD:    {"asimd", true},
	ARM64FeatureEVTSTRM:  {"evtstrm", true},
	ARM64FeatureAES:      {"aes", true},
	ARM64FeaturePMULL:    {"pmull", true},
	ARM64FeatureSHA1:     {"sha1", true},
	ARM64FeatureSHA2:     {"sha2", true},
	ARM64FeatureCRC32:    {"crc32", true},
	ARM64FeatureATOMICS:  {"atomics", true},
	ARM64FeatureFPHP:     {"fphp", true},
	ARM64FeatureASIMDHP:  {"asimdhp", true},
	ARM64FeatureCPUID:    {"cpuid", true},
	ARM64FeatureASIMDRDM: {"asimdrdm", true},
	ARM64FeatureJSCVT:    {"jscvt", true},
	ARM64FeatureFCMA:     {"fcma", true},
	ARM64FeatureLRCPC:    {"lrcpc", true},
	ARM64FeatureDCPOP:    {"dcpop", true},
	ARM64FeatureSHA3:     {"sha3", true},
	ARM64FeatureSM3:      {"sm3", true},
	ARM64FeatureSM4:      {"sm4", true},
	ARM64FeatureASIMDDP:  {"asimddp", true},
	ARM64FeatureSHA512:   {"sha512", true},
	ARM64FeatureSVE:      {"sve", true},
	ARM64FeatureASIMDFHM: {"asimdfhm", true},
}

func archFlagOrder(fn func(Feature)) {
	for i := 0; i < len(allFeatures); i++ {
		fn(Feature(i))
	}
}
