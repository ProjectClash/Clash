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

package cpuid

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/sync"
)

type contextID int

const (
	CtxFeatureSet contextID = iota

	_AT_HWCAP = 16
	_AT_HWCAP2 = 26
)

type anyContext interface {
	Value(key any) any
}

func FromContext(ctx anyContext) FeatureSet {
	v := ctx.Value(CtxFeatureSet)
	if v == nil {
		return FeatureSet{}
	}
	return v.(FeatureSet)
}

type Feature int

type allFeatureInfo struct {
	displayName string

	shouldAppear bool
}

func (f Feature) String() string {
	info, ok := allFeatures[f]
	if ok {
		return info.displayName
	}
	return fmt.Sprintf("[0x%x?]", int(f))
}

var reverseMap = func() map[string]Feature {
	m := make(map[string]Feature)
	for feature, info := range allFeatures {
		if info.displayName != "" {
			if old, ok := m[info.displayName]; ok {
				panic(fmt.Sprintf("feature %v has conflicting values (0x%x vs 0x%x)", info.displayName, old, feature))
			}
			m[info.displayName] = feature
		}
	}
	return m
}()

func FeatureFromString(s string) (Feature, bool) {
	feature, ok := reverseMap[s]
	return feature, ok
}

func AllFeatures() (features []Feature) {
	archFlagOrder(func(f Feature) {
		features = append(features, f)
	})
	return
}

func (fs FeatureSet) Subtract(other FeatureSet) (left map[Feature]struct{}) {
	for feature := range allFeatures {
		thisHas := fs.HasFeature(feature)
		otherHas := other.HasFeature(feature)
		if thisHas && !otherHas {
			if left == nil {
				left = make(map[Feature]struct{})
			}
			left[feature] = struct{}{}
		}
	}
	return
}

func (fs FeatureSet) FlagString() string {
	var s []string
	archFlagOrder(func(feature Feature) {
		if !fs.HasFeature(feature) {
			return
		}
		info := allFeatures[feature]
		if !info.shouldAppear {
			return
		}
		s = append(s, info.displayName)
	})
	return strings.Join(s, " ")
}

type ErrIncompatible struct {
	reason string
}

func (e *ErrIncompatible) Error() string {
	return fmt.Sprintf("incompatible FeatureSet: %v", e.reason)
}

func (fs FeatureSet) CheckHostCompatible() error {
	hfs := HostFeatureSet()

	if diff := fs.Subtract(hfs); len(diff) > 0 {
		return &ErrIncompatible{
			reason: fmt.Sprintf("missing features: %v", diff),
		}
	}

	return fs.archCheckHostCompatible(hfs)
}

type hwCap struct {
	hwCap1 uint64
	hwCap2 uint64
}

func readHWCap(auxvFilepath string) (hwCap, error) {
	c := hwCap{}
	if runtime.GOOS != "linux" {
		return c, fmt.Errorf("readHwCap only supported on linux, not %s", runtime.GOOS)
	}

	auxv, err := os.ReadFile(auxvFilepath)
	if err != nil {
		return c, fmt.Errorf("failed to read file %s: %w", auxvFilepath, err)
	}

	l := len(auxv) / 16
	for i := 0; i < l; i++ {
		tag := binary.LittleEndian.Uint64(auxv[i*16:])
		val := binary.LittleEndian.Uint64(auxv[i*16+8:])
		switch tag {
		case _AT_HWCAP:
			c.hwCap1 = val
		case _AT_HWCAP2:
			c.hwCap2 = val
		}

		if (c.hwCap1 != 0) && (c.hwCap2 != 0) {
			break
		}
	}
	return c, nil
}

func initHWCap() {
	c, err := readHWCap("/proc/self/auxv")
	if err != nil {
		log.Warningf("cpuid HWCap not initialized: %v", err)
	} else {
		hostFeatureSet.hwCap = c
	}
}

var initOnce sync.Once

func Initialize() {
	initOnce.Do(archInitialize)
}
