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

	"github.com/metacubex/gvisor/pkg/common"
)

type Static map[In]Out

func (fs FeatureSet) Fixed() FeatureSet {
	sfs := fs.ToStatic().ToFeatureSet()
	sfs.hwCap = fs.hwCap
	return sfs
}

func (fs FeatureSet) ToStatic() Static {
	s := make(Static)

	for fn, allowed := range allowedBasicFunctions {
		if allowed {
			in := In{Eax: uint32(fn)}
			s[in] = fs.Query(in)
		}
	}

	for fn, allowed := range allowedExtendedFunctions {
		if allowed {
			in := In{Eax: uint32(fn) + uint32(extendedStart)}
			s[in] = fs.Query(in)
		}
	}

	for feature := range allFeatures {
		feature.set(s, fs.HasFeature(feature))
	}

	for i := uint32(0); i < xSaveInfoNumLeaves; i++ {
		in := In{Eax: uint32(xSaveInfo), Ecx: i}
		s[in] = fs.Query(in)
	}

	out := fs.Query(In{Eax: uint32(featureInfo)})
	for i := uint32(0); i < out.Ecx; i++ {
		in := In{Eax: uint32(intelDeterministicCacheParams), Ecx: i}
		out := fs.Query(in)
		s[in] = out
		if CacheType(out.Eax&0xf) == cacheNull {
			break
		}
	}

	return s
}

func (s Static) ToFeatureSet() FeatureSet {
	ns := make(Static)
	for k, v := range s {
		ns[k] = v
	}
	ns.normalize()
	return FeatureSet{ns, hwCap{}}
}

func (s Static) afterLoad(context.Context) {
	s.normalize()
}

func (s Static) normalize() {
	fs := FeatureSet{s, hwCap{}}
	if fs.HasFeature(X86FeatureXSAVE) {
		in := In{Eax: uint32(xSaveInfo)}
		out := s[in]
		out.Ecx = common.Max(out.Ecx, maxXsaveSize)
		out.Ebx = common.Max(out.Ebx, xsaveSize)
		s[in] = out
	}
}

func (s Static) Add(feature Feature) Static {
	feature.set(s, true)
	return s
}

func (s Static) Remove(feature Feature) Static {
	feature.set(s, false)
	return s
}

func (s Static) Set(in In, out Out) {
	s[in] = out
}

func (s Static) Query(in In) Out {
	in.normalize()
	return s[in]
}
