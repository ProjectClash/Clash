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

package abi

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type FlagSet []struct {
	Flag uint64
	Name string
}

func (s FlagSet) Parse(val uint64) string {
	var flags []string

	for _, f := range s {
		if val&f.Flag == f.Flag {
			flags = append(flags, f.Name)
			val &^= f.Flag
		}
	}

	if val != 0 {
		flags = append(flags, "0x"+strconv.FormatUint(val, 16))
	}

	if len(flags) == 0 {
		return "0x0"
	}

	return strings.Join(flags, "|")
}

type ValueSet map[uint64]string

func (s ValueSet) Parse(val uint64) string {
	if v, ok := s[val]; ok {
		return v
	}
	return fmt.Sprintf("%#x", val)
}

func (s ValueSet) ParseDecimal(val uint64) string {
	if v, ok := s[val]; ok {
		return v
	}
	return fmt.Sprintf("%d", val)
}

func (s ValueSet) ParseName(name string) (uint64, bool) {
	for k, v := range s {
		if v == name {
			return k, true
		}
	}
	return math.MaxUint64, false
}
