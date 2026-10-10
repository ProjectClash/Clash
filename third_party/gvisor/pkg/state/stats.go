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

package state

import (
	"bytes"
	"fmt"
	"sort"
	"time"
)

type statEntry struct {
	count uint
	total time.Duration
}

type Stats struct {
	byType []statEntry

	stack []typeID

	names []string

	last time.Time
}

func (s *Stats) init() {
	s.last = time.Now()
	s.stack = append(s.stack, 0)
}

func (s *Stats) fini(resolve func(id typeID) string) {
	s.done()

	s.names = make([]string, len(s.byType))
	s.names[0] = "state.default"
	for id := typeID(1); int(id) < len(s.names); id++ {
		s.names[id] = resolve(id)
	}
}

func (s *Stats) sample(id typeID) {
	now := time.Now()
	if len(s.byType) <= int(id) {
		s.byType = append(s.byType, make([]statEntry, 1+int(id)-len(s.byType))...)
	}
	s.byType[id].total += now.Sub(s.last)
	s.last = now
}

func (s *Stats) start(id typeID) {
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.stack = append(s.stack, id)
}

func (s *Stats) done() {
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.byType[last].count++
	s.stack = s.stack[:len(s.stack)-1]
}

type sliceEntry struct {
	name  string
	entry *statEntry
}

func (s *Stats) String() string {
	ss := make([]sliceEntry, 0, len(s.byType))
	for id := 0; id < len(s.names); id++ {
		ss = append(ss, sliceEntry{
			name:  s.names[id],
			entry: &s.byType[id],
		})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].entry.total > ss[j].entry.total
	})

	var (
		buf   bytes.Buffer
		count uint
		total time.Duration
	)
	buf.WriteString("\n")
	fmt.Fprintf(&buf, "% 16s | % 8s | % 16s | %s\n", "total", "count", "per", "type")
	buf.WriteString("-----------------+----------+------------------+----------------\n")
	for _, se := range ss {
		if se.entry.count == 0 {
			continue
		}
		count += se.entry.count
		total += se.entry.total
		per := se.entry.total / time.Duration(se.entry.count)
		fmt.Fprintf(&buf, "% 16s | %8d | % 16s | %s\n",
			se.entry.total, se.entry.count, per, se.name)
	}
	buf.WriteString("-----------------+----------+------------------+----------------\n")
	fmt.Fprintf(&buf, "% 16s | % 8d | % 16s | [all]",
		total, count, total/time.Duration(count))
	return buf.String()
}
