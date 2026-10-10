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

package fspath

import (
	"strings"
)

const pathSep = '/'

func Parse(pathname string) Path {
	if len(pathname) == 0 {
		return Path{}
	}
	i := 0
	for pathname[i] == pathSep {
		i++
		if i == len(pathname) {
			return Path{
				Absolute: true,
				Dir:      true,
			}
		}
	}
	j := len(pathname) - 1
	for pathname[j] == pathSep {
		j--
	}
	firstEnd := i + 1
	for firstEnd != len(pathname) && pathname[firstEnd] != pathSep {
		firstEnd++
	}
	return Path{
		Begin: Iterator{
			partialPathname: pathname[i : j+1],
			end:             firstEnd - i,
		},
		Absolute: i != 0,
		Dir:      j != len(pathname)-1,
	}
}

type Path struct {
	Begin Iterator

	Absolute bool

	Dir bool
}

func (p Path) String() string {
	var b strings.Builder
	if p.Absolute {
		b.WriteByte(pathSep)
	}
	sep := false
	for pit := p.Begin; pit.Ok(); pit = pit.Next() {
		if sep {
			b.WriteByte(pathSep)
		}
		b.WriteString(pit.String())
		sep = true
	}
	if p.Dir && p.Begin.Ok() {
		b.WriteByte(pathSep)
	}
	return b.String()
}

func (p Path) HasComponents() bool {
	return p.Begin.Ok()
}

type Iterator struct {
	partialPathname string

	end int
}

func (it Iterator) Ok() bool {
	return len(it.partialPathname) != 0
}

func (it Iterator) String() string {
	return it.partialPathname[:it.end]
}

func (it Iterator) Next() Iterator {
	if it.end == len(it.partialPathname) {
		return Iterator{}
	}
	i := it.end + 1
	for it.partialPathname[i] == pathSep {
		i++
	}
	nextPartialPathname := it.partialPathname[i:]
	nextEnd := 1
	for nextEnd < len(nextPartialPathname) && nextPartialPathname[nextEnd] != pathSep {
		nextEnd++
	}
	return Iterator{
		partialPathname: nextPartialPathname,
		end:             nextEnd,
	}
}

func (it Iterator) NextOk() bool {
	return it.end != len(it.partialPathname)
}
