// Copyright 2021 The gVisor Authors.
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

package ports

type Flags struct {
	MostRecent bool

	LoadBalanced bool

	TupleOnly bool
}

func (f Flags) Bits() BitFlags {
	var rf BitFlags
	if f.MostRecent {
		rf |= MostRecentFlag
	}
	if f.LoadBalanced {
		rf |= LoadBalancedFlag
	}
	if f.TupleOnly {
		rf |= TupleOnlyFlag
	}
	return rf
}

func (f Flags) Effective() Flags {
	e := f
	if e.LoadBalanced && e.MostRecent {
		e.MostRecent = false
	}
	return e
}

type BitFlags uint32

const (
	MostRecentFlag BitFlags = 1 << iota

	LoadBalancedFlag

	TupleOnlyFlag

	nextFlag

	FlagMask = nextFlag - 1

	MultiBindFlagMask = MostRecentFlag | LoadBalancedFlag
)

func (f BitFlags) ToFlags() Flags {
	return Flags{
		MostRecent:   f&MostRecentFlag != 0,
		LoadBalanced: f&LoadBalancedFlag != 0,
		TupleOnly:    f&TupleOnlyFlag != 0,
	}
}

type FlagCounter struct {
	refs [nextFlag]int
}

func (c *FlagCounter) AddRef(flags BitFlags) {
	c.refs[flags]++
}

func (c *FlagCounter) DropRef(flags BitFlags) {
	c.refs[flags]--
}

func (c FlagCounter) TotalRefs() int {
	var total int
	for _, r := range c.refs {
		total += r
	}
	return total
}

func (c FlagCounter) FlagRefs(flags BitFlags) int {
	var total int
	for i, r := range c.refs {
		if BitFlags(i)&flags == flags {
			total += r
		}
	}
	return total
}

func (c FlagCounter) AllRefsHave(flags BitFlags) bool {
	for i, r := range c.refs {
		if BitFlags(i)&flags != flags && r > 0 {
			return false
		}
	}
	return true
}

func (c FlagCounter) SharedFlags() BitFlags {
	intersection := FlagMask
	for i, r := range c.refs {
		if r > 0 {
			intersection &= BitFlags(i)
		}
	}
	return intersection
}
