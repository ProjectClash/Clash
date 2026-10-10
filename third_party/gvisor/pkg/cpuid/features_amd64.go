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

type block int

const blockSize = 32

func featureID(b block, bit int) Feature {
	return Feature(blockSize*int(b) + bit)
}

func (f Feature) block() block {
	return block(f / blockSize)
}

func (f Feature) bit() uint32 {
	return uint32(1 << (f % blockSize))
}

type ChangeableSet interface {
	Query(in In) Out
	Set(in In, out Out)
}

func (f Feature) Set(s ChangeableSet) {
	f.set(s, true)
}

func (f Feature) Unset(s ChangeableSet) {
	f.set(s, false)
}

func (f Feature) set(s ChangeableSet, on bool) {
	switch f.block() {
	case 0:
		out := s.Query(In{Eax: uint32(featureInfo)})
		if on {
			out.Ecx |= f.bit()
		} else {
			out.Ecx &^= f.bit()
		}
		s.Set(In{Eax: uint32(featureInfo)}, out)
	case 1:
		out := s.Query(In{Eax: uint32(featureInfo)})
		if on {
			out.Edx |= f.bit()
		} else {
			out.Edx &^= f.bit()
		}
		s.Set(In{Eax: uint32(featureInfo)}, out)
	case 2:
		out := s.Query(In{Eax: uint32(extendedFeatureInfo)})
		if on {
			out.Ebx |= f.bit()
		} else {
			out.Ebx &^= f.bit()
		}
		s.Set(In{Eax: uint32(extendedFeatureInfo)}, out)
	case 3:
		out := s.Query(In{Eax: uint32(extendedFeatureInfo)})
		if on {
			out.Ecx |= f.bit()
		} else {
			out.Ecx &^= f.bit()
		}
		s.Set(In{Eax: uint32(extendedFeatureInfo)}, out)
	case 4:
		out := s.Query(In{Eax: uint32(featureInfo)})
		out.Ecx |= (1 << 26)
		s.Set(In{Eax: uint32(featureInfo)}, out)

		out = s.Query(In{Eax: xSaveInfoSub.eax(), Ecx: xSaveInfoSub.ecx()})
		if on {
			out.Eax |= f.bit()
		} else {
			out.Eax &^= f.bit()
		}
		s.Set(In{Eax: xSaveInfoSub.eax(), Ecx: xSaveInfoSub.ecx()}, out)
	case 5, 6:
		out := s.Query(In{Eax: uint32(extendedFunctionInfo)})
		if out.Eax < uint32(extendedFeatures) {
			out.Eax = uint32(extendedFeatures)
		}
		s.Set(In{Eax: uint32(extendedFunctionInfo)}, out)
		out = s.Query(In{Eax: uint32(extendedFeatures)})
		if f.block() == 5 {
			if on {
				out.Ecx |= f.bit()
			} else {
				out.Ecx &^= f.bit()
			}
		} else {
			if on {
				out.Edx |= f.bit()
			} else {
				out.Edx &^= f.bit()
			}
		}
		s.Set(In{Eax: uint32(extendedFeatures)}, out)
	case 7:
		out := s.Query(In{Eax: uint32(extendedFeatureInfo)})
		if on {
			out.Edx |= f.bit()
		} else {
			out.Edx &^= f.bit()
		}
		s.Set(In{Eax: uint32(extendedFeatureInfo)}, out)
	}
}

// check checks for the given feature.
//
//go:nosplit
func (f Feature) check(fs FeatureSet) bool {
	switch f.block() {
	case 0:
		_, _, cx, _ := fs.query(featureInfo)
		return (cx & f.bit()) != 0
	case 1:
		_, _, _, dx := fs.query(featureInfo)
		return (dx & f.bit()) != 0
	case 2:
		_, bx, _, _ := fs.query(extendedFeatureInfo)
		return (bx & f.bit()) != 0
	case 3:
		_, _, cx, _ := fs.query(extendedFeatureInfo)
		return (cx & f.bit()) != 0
	case 4:
		_, _, cx, _ := fs.query(featureInfo)
		if (cx & (1 << 26)) == 0 {
			return false
		}
		ax, _, _, _ := fs.query(xSaveInfoSub)
		return (ax & f.bit()) != 0
	case 5, 6:
		ax, _, _, _ := fs.query(extendedFunctionInfo)
		if ax >= uint32(extendedFeatures) {
			_, _, cx, dx := fs.query(extendedFeatures)
			if f.block() == 5 {
				return (cx & f.bit()) != 0
			}
			return ((dx &^ block6DuplicateMask) & f.bit()) != 0
		}
		return false
	case 7:
		_, _, _, dx := fs.query(extendedFeatureInfo)
		return (dx & f.bit()) != 0
	default:
		return false
	}
}

const (
	X86FeatureSSE3 Feature = iota
	X86FeaturePCLMULDQ
	X86FeatureDTES64
	X86FeatureMONITOR
	X86FeatureDSCPL
	X86FeatureVMX
	X86FeatureSMX
	X86FeatureEST
	X86FeatureTM2
	X86FeatureSSSE3
	X86FeatureCNXTID
	X86FeatureSDBG
	X86FeatureFMA
	X86FeatureCX16
	X86FeatureXTPR
	X86FeaturePDCM
	_
	X86FeaturePCID
	X86FeatureDCA
	X86FeatureSSE4_1
	X86FeatureSSE4_2
	X86FeatureX2APIC
	X86FeatureMOVBE
	X86FeaturePOPCNT
	X86FeatureTSCD
	X86FeatureAES
	X86FeatureXSAVE
	X86FeatureOSXSAVE
	X86FeatureAVX
	X86FeatureF16C
	X86FeatureRDRAND
	X86FeatureHypervisor
)

const (
	X86FeatureFPU Feature = 32 + iota
	X86FeatureVME
	X86FeatureDE
	X86FeaturePSE
	X86FeatureTSC
	X86FeatureMSR
	X86FeaturePAE
	X86FeatureMCE
	X86FeatureCX8
	X86FeatureAPIC
	_
	X86FeatureSEP
	X86FeatureMTRR
	X86FeaturePGE
	X86FeatureMCA
	X86FeatureCMOV
	X86FeaturePAT
	X86FeaturePSE36
	X86FeaturePSN
	X86FeatureCLFSH
	_
	X86FeatureDS
	X86FeatureACPI
	X86FeatureMMX
	X86FeatureFXSR
	X86FeatureSSE
	X86FeatureSSE2
	X86FeatureSS
	X86FeatureHTT
	X86FeatureTM
	X86FeatureIA64
	X86FeaturePBE
)

const (
	X86FeatureFSGSBase Feature = 2*32 + iota
	X86FeatureTSC_ADJUST
	_
	X86FeatureBMI1
	X86FeatureHLE
	X86FeatureAVX2
	X86FeatureFDP_EXCPTN_ONLY
	X86FeatureSMEP
	X86FeatureBMI2
	X86FeatureERMS
	X86FeatureINVPCID
	X86FeatureRTM
	X86FeatureCQM
	X86FeatureFPCSDS
	X86FeatureMPX
	X86FeatureRDT
	X86FeatureAVX512F
	X86FeatureAVX512DQ
	X86FeatureRDSEED
	X86FeatureADX
	X86FeatureSMAP
	X86FeatureAVX512IFMA
	X86FeaturePCOMMIT
	X86FeatureCLFLUSHOPT
	X86FeatureCLWB
	X86FeatureIPT
	X86FeatureAVX512PF
	X86FeatureAVX512ER
	X86FeatureAVX512CD
	X86FeatureSHA
	X86FeatureAVX512BW
	X86FeatureAVX512VL
)

const (
	X86FeaturePREFETCHWT1 Feature = 3*32 + iota
	X86FeatureAVX512VBMI
	X86FeatureUMIP
	X86FeaturePKU
	X86FeatureOSPKE
	X86FeatureWAITPKG
	X86FeatureAVX512_VBMI2
	X86FeatureCET_SS
	X86FeatureGFNI
	X86FeatureVAES
	X86FeatureVPCLMULQDQ
	X86FeatureAVX512_VNNI
	X86FeatureAVX512_BITALG
	X86FeatureTME
	X86FeatureAVX512_VPOPCNTDQ
	_
	X86FeatureLA57
	_
	_
	_
	_
	_
	X86FeatureRDPID
	_
	_
	X86FeatureCLDEMOTE
	_
	X86FeatureMOVDIRI
	X86FeatureMOVDIR64B
)

const (
	X86FeatureXSAVEOPT Feature = 4*32 + iota
	X86FeatureXSAVEC
	X86FeatureXGETBV1
	X86FeatureXSAVES
)

const (
	X86FeatureLAHF64 Feature = 5*32 + iota
	X86FeatureCMP_LEGACY
	X86FeatureSVM
	X86FeatureEXTAPIC
	X86FeatureCR8_LEGACY
	X86FeatureLZCNT
	X86FeatureSSE4A
	X86FeatureMISALIGNSSE
	X86FeaturePREFETCHW
	X86FeatureOSVW
	X86FeatureIBS
	X86FeatureXOP
	X86FeatureSKINIT
	X86FeatureWDT
	_
	X86FeatureLWP
	X86FeatureFMA4
	X86FeatureTCE
	_
	_
	_
	X86FeatureTBM
	X86FeatureTOPOLOGY
	X86FeaturePERFCTR_CORE
	X86FeaturePERFCTR_NB
	_
	X86FeatureBPEXT
	X86FeaturePERFCTR_TSC
	X86FeaturePERFCTR_LLC
	X86FeatureMWAITX
	X86FeatureADMSKEXTN
	_
)

const (
	block6DuplicateMask = 0x183f3ff

	X86FeatureSYSCALL  Feature = 6*32 + 11
	X86FeatureNX       Feature = 6*32 + 20
	X86FeatureMMXEXT   Feature = 6*32 + 22
	X86FeatureFXSR_OPT Feature = 6*32 + 25
	X86FeatureGBPAGES  Feature = 6*32 + 26
	X86FeatureRDTSCP   Feature = 6*32 + 27
	X86FeatureLM       Feature = 6*32 + 29
	X86Feature3DNOWEXT Feature = 6*32 + 30
	X86Feature3DNOW    Feature = 6*32 + 31
)

const (
	_ Feature = 7*32 + iota
	_
	X86FeatureAVX512_4VNNIW
	X86FeatureAVX512_4FMAPS
	X86FeatureFSRM
	_
	_
	_
	X86FeatureAVX512_VP2INTERSECT
	X86FeatureSRBDS_CTRL
	X86FeatureMD_CLEAR
	X86FeatureRTM_ALWAYS_ABORT
	_
	X86FeatureTSX_FORCE_ABORT
	X86FeatureSERIALIZE
	X86FeatureHYBRID_CPU
	X86FeatureTSXLDTRK
	_
	X86FeaturePCONFIG
	X86FeatureARCH_LBR
	X86FeatureIBT
	_
	X86FeatureAMX_BF16
	X86FeatureAVX512_FP16
	X86FeatureAMX_TILE
	X86FeatureAMX_INT8
	X86FeatureSPEC_CTRL
	X86FeatureINTEL_STIBP
	X86FeatureFLUSH_L1D
	X86FeatureARCH_CAPABILITIES
	X86FeatureCORE_CAPABILITIES
	X86FeatureSPEC_CTRL_SSBD
)

const (
	XSAVEFeatureX87         = 1 << 0
	XSAVEFeatureSSE         = 1 << 1
	XSAVEFeatureAVX         = 1 << 2
	XSAVEFeatureBNDREGS     = 1 << 3
	XSAVEFeatureBNDCSR      = 1 << 4
	XSAVEFeatureAVX512op    = 1 << 5
	XSAVEFeatureAVX512zmm0  = 1 << 6
	XSAVEFeatureAVX512zmm16 = 1 << 7
	XSAVEFeaturePKRU        = 1 << 9
)

var allFeatures = map[Feature]allFeatureInfo{
	X86FeatureSSE3:       {"pni", true},
	X86FeaturePCLMULDQ:   {"pclmulqdq", true},
	X86FeatureDTES64:     {"dtes64", true},
	X86FeatureMONITOR:    {"monitor", true},
	X86FeatureDSCPL:      {"ds_cpl", true},
	X86FeatureVMX:        {"vmx", true},
	X86FeatureSMX:        {"smx", true},
	X86FeatureEST:        {"est", true},
	X86FeatureTM2:        {"tm2", true},
	X86FeatureSSSE3:      {"ssse3", true},
	X86FeatureCNXTID:     {"cid", true},
	X86FeatureSDBG:       {"sdbg", true},
	X86FeatureFMA:        {"fma", true},
	X86FeatureCX16:       {"cx16", true},
	X86FeatureXTPR:       {"xtpr", true},
	X86FeaturePDCM:       {"pdcm", true},
	X86FeaturePCID:       {"pcid", true},
	X86FeatureDCA:        {"dca", true},
	X86FeatureSSE4_1:     {"sse4_1", true},
	X86FeatureSSE4_2:     {"sse4_2", true},
	X86FeatureX2APIC:     {"x2apic", true},
	X86FeatureMOVBE:      {"movbe", true},
	X86FeaturePOPCNT:     {"popcnt", true},
	X86FeatureTSCD:       {"tsc_deadline_timer", true},
	X86FeatureAES:        {"aes", true},
	X86FeatureXSAVE:      {"xsave", true},
	X86FeatureAVX:        {"avx", true},
	X86FeatureF16C:       {"f16c", true},
	X86FeatureRDRAND:     {"rdrand", true},
	X86FeatureHypervisor: {"hypervisor", true},
	X86FeatureOSXSAVE:    {"osxsave", false},

	X86FeatureFPU:   {"fpu", true},
	X86FeatureVME:   {"vme", true},
	X86FeatureDE:    {"de", true},
	X86FeaturePSE:   {"pse", true},
	X86FeatureTSC:   {"tsc", true},
	X86FeatureMSR:   {"msr", true},
	X86FeaturePAE:   {"pae", true},
	X86FeatureMCE:   {"mce", true},
	X86FeatureCX8:   {"cx8", true},
	X86FeatureAPIC:  {"apic", true},
	X86FeatureSEP:   {"sep", true},
	X86FeatureMTRR:  {"mtrr", true},
	X86FeaturePGE:   {"pge", true},
	X86FeatureMCA:   {"mca", true},
	X86FeatureCMOV:  {"cmov", true},
	X86FeaturePAT:   {"pat", true},
	X86FeaturePSE36: {"pse36", true},
	X86FeaturePSN:   {"pn", true},
	X86FeatureCLFSH: {"clflush", true},
	X86FeatureDS:    {"dts", true},
	X86FeatureACPI:  {"acpi", true},
	X86FeatureMMX:   {"mmx", true},
	X86FeatureFXSR:  {"fxsr", true},
	X86FeatureSSE:   {"sse", true},
	X86FeatureSSE2:  {"sse2", true},
	X86FeatureSS:    {"ss", true},
	X86FeatureHTT:   {"ht", true},
	X86FeatureTM:    {"tm", true},
	X86FeatureIA64:  {"ia64", true},
	X86FeaturePBE:   {"pbe", true},

	X86FeatureFSGSBase:        {"fsgsbase", true},
	X86FeatureTSC_ADJUST:      {"tsc_adjust", true},
	X86FeatureBMI1:            {"bmi1", true},
	X86FeatureHLE:             {"hle", true},
	X86FeatureAVX2:            {"avx2", true},
	X86FeatureSMEP:            {"smep", true},
	X86FeatureBMI2:            {"bmi2", true},
	X86FeatureERMS:            {"erms", true},
	X86FeatureINVPCID:         {"invpcid", true},
	X86FeatureRTM:             {"rtm", true},
	X86FeatureCQM:             {"cqm", true},
	X86FeatureMPX:             {"mpx", true},
	X86FeatureRDT:             {"rdt_a", true},
	X86FeatureAVX512F:         {"avx512f", true},
	X86FeatureAVX512DQ:        {"avx512dq", true},
	X86FeatureRDSEED:          {"rdseed", true},
	X86FeatureADX:             {"adx", true},
	X86FeatureSMAP:            {"smap", true},
	X86FeatureCLWB:            {"clwb", true},
	X86FeatureAVX512PF:        {"avx512pf", true},
	X86FeatureAVX512ER:        {"avx512er", true},
	X86FeatureAVX512CD:        {"avx512cd", true},
	X86FeatureSHA:             {"sha_ni", true},
	X86FeatureAVX512BW:        {"avx512bw", true},
	X86FeatureAVX512VL:        {"avx512vl", true},
	X86FeatureFDP_EXCPTN_ONLY: {"fdp_excptn_only", false},
	X86FeatureFPCSDS:          {"fpcsds", false},
	X86FeatureIPT:             {"ipt", false},
	X86FeatureCLFLUSHOPT:      {"clfushopt", false},

	X86FeatureAVX512VBMI:       {"avx512vbmi", true},
	X86FeatureUMIP:             {"umip", true},
	X86FeaturePKU:              {"pku", true},
	X86FeatureOSPKE:            {"ospke", true},
	X86FeatureWAITPKG:          {"waitpkg", true},
	X86FeatureAVX512_VBMI2:     {"avx512_vbmi2", true},
	X86FeatureGFNI:             {"gfni", true},
	X86FeatureCET_SS:           {"cet_ss", false},
	X86FeatureVAES:             {"vaes", true},
	X86FeatureVPCLMULQDQ:       {"vpclmulqdq", true},
	X86FeatureAVX512_VNNI:      {"avx512_vnni", true},
	X86FeatureAVX512_BITALG:    {"avx512_bitalg", true},
	X86FeatureTME:              {"tme", true},
	X86FeatureAVX512_VPOPCNTDQ: {"avx512_vpopcntdq", true},
	X86FeatureLA57:             {"la57", true},
	X86FeatureRDPID:            {"rdpid", true},
	X86FeatureCLDEMOTE:         {"cldemote", true},
	X86FeatureMOVDIRI:          {"movdiri", true},
	X86FeatureMOVDIR64B:        {"movdir64b", true},
	X86FeaturePREFETCHWT1:      {"prefetchwt1", false},

	X86FeatureXSAVEOPT: {"xsaveopt", true},
	X86FeatureXSAVEC:   {"xsavec", true},
	X86FeatureXGETBV1:  {"xgetbv1", true},
	X86FeatureXSAVES:   {"xsaves", true},

	X86FeatureLAHF64:       {"lahf_lm", true},
	X86FeatureCMP_LEGACY:   {"cmp_legacy", true},
	X86FeatureSVM:          {"svm", true},
	X86FeatureEXTAPIC:      {"extapic", true},
	X86FeatureCR8_LEGACY:   {"cr8_legacy", true},
	X86FeatureLZCNT:        {"abm", true},
	X86FeatureSSE4A:        {"sse4a", true},
	X86FeatureMISALIGNSSE:  {"misalignsse", true},
	X86FeaturePREFETCHW:    {"3dnowprefetch", true},
	X86FeatureOSVW:         {"osvw", true},
	X86FeatureIBS:          {"ibs", true},
	X86FeatureXOP:          {"xop", true},
	X86FeatureSKINIT:       {"skinit", true},
	X86FeatureWDT:          {"wdt", true},
	X86FeatureLWP:          {"lwp", true},
	X86FeatureFMA4:         {"fma4", true},
	X86FeatureTCE:          {"tce", true},
	X86FeatureTBM:          {"tbm", true},
	X86FeatureTOPOLOGY:     {"topoext", true},
	X86FeaturePERFCTR_CORE: {"perfctr_core", true},
	X86FeaturePERFCTR_NB:   {"perfctr_nb", true},
	X86FeatureBPEXT:        {"bpext", true},
	X86FeaturePERFCTR_TSC:  {"ptsc", true},
	X86FeaturePERFCTR_LLC:  {"perfctr_llc", true},
	X86FeatureMWAITX:       {"mwaitx", true},
	X86FeatureADMSKEXTN:    {"ad_mask_extn", false},

	X86FeatureSYSCALL:  {"syscall", true},
	X86FeatureNX:       {"nx", true},
	X86FeatureMMXEXT:   {"mmxext", true},
	X86FeatureFXSR_OPT: {"fxsr_opt", true},
	X86FeatureGBPAGES:  {"pdpe1gb", true},
	X86FeatureRDTSCP:   {"rdtscp", true},
	X86FeatureLM:       {"lm", true},
	X86Feature3DNOWEXT: {"3dnowext", true},
	X86Feature3DNOW:    {"3dnow", true},

	X86FeatureAVX512_4VNNIW:       {"avx512_4vnniw", true},
	X86FeatureAVX512_4FMAPS:       {"avx512_4fmaps", true},
	X86FeatureFSRM:                {"fsrm", true},
	X86FeatureAVX512_VP2INTERSECT: {"avx512_vp2intersect", true},
	X86FeatureSRBDS_CTRL:          {"srbds_ctrl", false},
	X86FeatureMD_CLEAR:            {"md_clear", true},
	X86FeatureRTM_ALWAYS_ABORT:    {"rtm_always_abort", false},
	X86FeatureTSX_FORCE_ABORT:     {"tsx_force_abort", false},
	X86FeatureSERIALIZE:           {"serialize", true},
	X86FeatureHYBRID_CPU:          {"hybrid_cpu", false},
	X86FeatureTSXLDTRK:            {"tsxldtrk", true},
	X86FeaturePCONFIG:             {"pconfig", true},
	X86FeatureARCH_LBR:            {"arch_lbr", true},
	X86FeatureIBT:                 {"ibt", true},
	X86FeatureAMX_BF16:            {"amx_bf16", true},
	X86FeatureAVX512_FP16:         {"avx512_fp16", true},
	X86FeatureAMX_TILE:            {"amx_tile", true},
	X86FeatureAMX_INT8:            {"amx_int8", true},
	X86FeatureSPEC_CTRL:           {"spec_ctrl", false},
	X86FeatureINTEL_STIBP:         {"intel_stibp", false},
	X86FeatureFLUSH_L1D:           {"flush_l1d", true},
	X86FeatureARCH_CAPABILITIES:   {"arch_capabilities", true},
	X86FeatureCORE_CAPABILITIES:   {"core_capabilities", false},
	X86FeatureSPEC_CTRL_SSBD:      {"spec_ctrl_ssbd", false},
}

var linuxBlockOrder = []block{1, 6, 0, 5, 2, 4, 3, 7}

func archFlagOrder(fn func(Feature)) {
	for _, b := range linuxBlockOrder {
		for i := 0; i < blockSize; i++ {
			f := featureID(b, i)
			if _, ok := allFeatures[f]; ok {
				fn(f)
			}
		}
	}
}
