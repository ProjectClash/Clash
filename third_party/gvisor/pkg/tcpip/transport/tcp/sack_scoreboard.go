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

package tcp

import (
	"fmt"
	"strings"

	"github.com/google/btree"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
)

const (
	maxSACKBlocks = 100

	defaultBtreeDegree = 2
)

func sackBlockLess(a, b header.SACKBlock) bool {
	return a.Start.LessThan(b.Start)
}

type SACKScoreboard struct {
	smss      uint16
	maxSACKED seqnum.Value
	sacked    seqnum.Size                     `state:"nosave"`
	ranges    *btree.BTreeG[header.SACKBlock] `state:"nosave"`
}

func NewSACKScoreboard(smss uint16, iss seqnum.Value) *SACKScoreboard {
	return &SACKScoreboard{
		smss:      smss,
		ranges:    btree.NewG[header.SACKBlock](defaultBtreeDegree, sackBlockLess),
		maxSACKED: iss,
	}
}

func (s *SACKScoreboard) Reset() {
	s.ranges = btree.NewG[header.SACKBlock](defaultBtreeDegree, sackBlockLess)
	s.sacked = 0
}

func (s *SACKScoreboard) Insert(r header.SACKBlock) {
	if s.ranges.Len() >= maxSACKBlocks {
		return
	}

	var toDelete []header.SACKBlock
	if s.maxSACKED.LessThan(r.End - 1) {
		s.maxSACKED = r.End - 1
	}
	s.ranges.AscendGreaterOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked == r {
			return true
		}
		if r.End.LessThan(sacked.Start) {
			return false
		}
		if sacked.End.LessThan(r.End) {
			toDelete = append(toDelete, sacked)
			return true
		}
		r.End = sacked.End
		toDelete = append(toDelete, sacked)
		return true
	})

	s.ranges.DescendLessOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked == r {
			return true
		}
		if sacked.End.LessThan(r.Start) {
			return false
		}
		r.Start = sacked.Start
		if r.End.LessThan(sacked.End) {
			r.End = sacked.End
		}
		toDelete = append(toDelete, sacked)
		return true
	})
	for _, sb := range toDelete {
		if _, ok := s.ranges.Delete(sb); ok {
			s.sacked -= sb.Start.Size(sb.End)
		}
	}

	_, replaced := s.ranges.ReplaceOrInsert(r)
	if !replaced {
		s.sacked += r.Start.Size(r.End)
	}
}

func (s *SACKScoreboard) IsSACKED(r header.SACKBlock) bool {
	if s.Empty() {
		return false
	}

	found := false
	s.ranges.DescendLessOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked.End.LessThan(r.Start) {
			return false
		}
		if sacked.Contains(r) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (s *SACKScoreboard) String() string {
	var str strings.Builder
	str.WriteString("SACKScoreboard: {")
	s.ranges.Ascend(func(sb header.SACKBlock) bool {
		fmt.Fprintf(&str, "%v,", sb)
		return true
	})
	str.WriteString("}\n")
	return str.String()
}

func (s *SACKScoreboard) Delete(seq seqnum.Value) {
	if s.Empty() {
		return
	}
	var toDelete []header.SACKBlock
	var toInsert []header.SACKBlock
	r := header.SACKBlock{seq, seq.Add(1)}
	s.ranges.DescendLessOrEqual(r, func(sb header.SACKBlock) bool {
		if sb == r {
			return true
		}
		toDelete = append(toDelete, sb)
		if sb.End.LessThanEq(seq) {
			s.sacked -= sb.Start.Size(sb.End)
		} else {
			newSB := header.SACKBlock{seq, sb.End}
			toInsert = append(toInsert, newSB)
			s.sacked -= sb.Start.Size(seq)
		}
		return true
	})
	for _, sb := range toDelete {
		s.ranges.Delete(sb)
	}
	for _, sb := range toInsert {
		s.ranges.ReplaceOrInsert(sb)
	}
}

func (s *SACKScoreboard) Copy() (sackBlocks []header.SACKBlock, maxSACKED seqnum.Value) {
	s.ranges.Ascend(func(sb header.SACKBlock) bool {
		sackBlocks = append(sackBlocks, sb)
		return true
	})
	return sackBlocks, s.maxSACKED
}

func (s *SACKScoreboard) IsRangeLost(r header.SACKBlock) bool {
	if s.Empty() {
		return false
	}
	nDupSACK := 0
	nDupSACKBytes := seqnum.Size(0)
	isLost := false

	searchMore := true
	s.ranges.DescendLessOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked.Contains(r) {
			searchMore = false
			return false
		}
		if sacked.End.LessThanEq(r.Start) {
			return false
		}
		r.Start = sacked.End
		return false
	})

	if !searchMore {
		return isLost
	}

	s.ranges.AscendGreaterOrEqual(r, func(sacked header.SACKBlock) bool {
		if sacked.Contains(r) {
			return false
		}
		nDupSACKBytes += sacked.Start.Size(sacked.End)
		nDupSACK++
		if nDupSACK >= nDupAckThreshold || nDupSACKBytes >= seqnum.Size((nDupAckThreshold-1)*s.smss) {
			isLost = true
			return false
		}
		return true
	})
	return isLost
}

func (s *SACKScoreboard) IsLost(seq seqnum.Value) bool {
	return s.IsRangeLost(header.SACKBlock{seq, seq.Add(1)})
}

func (s *SACKScoreboard) Empty() bool {
	return s.ranges.Len() == 0
}

func (s *SACKScoreboard) Sacked() seqnum.Size {
	return s.sacked
}

func (s *SACKScoreboard) MaxSACKED() seqnum.Value {
	return s.maxSACKED
}

func (s *SACKScoreboard) SMSS() uint16 {
	return s.smss
}
