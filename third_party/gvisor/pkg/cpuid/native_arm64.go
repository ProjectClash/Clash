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

//go:build arm64
// +build arm64

package cpuid

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/metacubex/gvisor/pkg/log"
)

var hostFeatureSet FeatureSet

func HostFeatureSet() FeatureSet {
	return hostFeatureSet
}

func (fs FeatureSet) Fixed() FeatureSet {
	return fs
}

func (fs FeatureSet) Intersect(allowedFeatures map[Feature]struct{}) (FeatureSet, error) {
	return FeatureSet{}, fmt.Errorf("FeatureSet intersection is not supported on ARM64")
}

func initCPUInfo() {
	if runtime.GOOS != "linux" {
		return
	}
	cpuinfob, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	cpuinfo := string(cpuinfob)

	for _, line := range strings.Split(cpuinfo, "\n") {
		switch {
		case strings.Contains(line, "BogoMIPS"):
			splitMHz := strings.Split(line, ":")
			if len(splitMHz) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed BogoMIPS")
				break
			}

			var err error
			hostFeatureSet.cpuFreqMHz, err = strconv.ParseFloat(strings.TrimSpace(splitMHz[1]), 64)
			if err != nil {
				hostFeatureSet.cpuFreqMHz = 0.0
				log.Warningf("Could not parse BogoMIPS value %v: %v", splitMHz[1], err)
			}
		case strings.Contains(line, "CPU implementer"):
			splitImpl := strings.Split(line, ":")
			if len(splitImpl) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU implementer")
				break
			}

			var err error
			hostFeatureSet.cpuImplHex, err = strconv.ParseUint(strings.TrimSpace(splitImpl[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuImplHex = 0
				log.Warningf("Could not parse CPU implementer value %v: %v", splitImpl[1], err)
			}
		case strings.Contains(line, "CPU architecture"):
			splitArch := strings.Split(line, ":")
			if len(splitArch) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU architecture")
				break
			}

			var err error
			hostFeatureSet.cpuArchDec, err = strconv.ParseUint(strings.TrimSpace(splitArch[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuArchDec = 0
				log.Warningf("Could not parse CPU architecture value %v: %v", splitArch[1], err)
			}
		case strings.Contains(line, "CPU variant"):
			splitVar := strings.Split(line, ":")
			if len(splitVar) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU variant")
				break
			}

			var err error
			hostFeatureSet.cpuVarHex, err = strconv.ParseUint(strings.TrimSpace(splitVar[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuVarHex = 0
				log.Warningf("Could not parse CPU variant value %v: %v", splitVar[1], err)
			}
		case strings.Contains(line, "CPU part"):
			splitPart := strings.Split(line, ":")
			if len(splitPart) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU part")
				break
			}

			var err error
			hostFeatureSet.cpuPartHex, err = strconv.ParseUint(strings.TrimSpace(splitPart[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuPartHex = 0
				log.Warningf("Could not parse CPU part value %v: %v", splitPart[1], err)
			}
		case strings.Contains(line, "CPU revision"):
			splitRev := strings.Split(line, ":")
			if len(splitRev) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU revision")
				break
			}

			var err error
			hostFeatureSet.cpuRevDec, err = strconv.ParseUint(strings.TrimSpace(splitRev[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuRevDec = 0
				log.Warningf("Could not parse CPU revision value %v: %v", splitRev[1], err)
			}
		}
	}
}

func archInitialize() {
	initCPUInfo()
	initHWCap()
}
