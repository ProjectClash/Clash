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
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
)

const (
	MaxSACKBlocks = 6
)

func UpdateSACKBlocks(sack *SACKInfo, segStart seqnum.Value, segEnd seqnum.Value, rcvNxt seqnum.Value) {
	newSB := header.SACKBlock{Start: segStart, End: segEnd}

	if newSB.End.LessThanEq(newSB.Start) || newSB.End.LessThan(rcvNxt) {
		return
	}

	if sack.NumBlocks == 0 {
		sack.Blocks[0] = newSB
		sack.NumBlocks = 1
		return
	}
	var n = 0
	for i := 0; i < sack.NumBlocks; i++ {
		start, end := sack.Blocks[i].Start, sack.Blocks[i].End
		if end.LessThanEq(rcvNxt) {
			continue
		}
		if newSB.Start.LessThanEq(end) && start.LessThanEq(newSB.End) {
			if start.LessThan(newSB.Start) {
				newSB.Start = start
			}
			if newSB.End.LessThan(end) {
				newSB.End = end
			}
		} else {
			sack.Blocks[n] = sack.Blocks[i]
			n++
		}
	}
	if rcvNxt.LessThan(newSB.Start) {
		if n == MaxSACKBlocks {
			n--
		}
		for i := n - 1; i >= 0; i-- {
			sack.Blocks[i+1] = sack.Blocks[i]
		}
		sack.Blocks[0] = newSB
		n++
	}
	sack.NumBlocks = n
}

func TrimSACKBlockList(sack *SACKInfo, rcvNxt seqnum.Value) {
	n := 0
	for i := 0; i < sack.NumBlocks; i++ {
		if sack.Blocks[i].End.LessThanEq(rcvNxt) {
			continue
		}
		if sack.Blocks[i].Start.LessThan(rcvNxt) {
			sack.Blocks[i].Start = rcvNxt
		}
		sack.Blocks[n] = sack.Blocks[i]
		n++
	}
	sack.NumBlocks = n
}
