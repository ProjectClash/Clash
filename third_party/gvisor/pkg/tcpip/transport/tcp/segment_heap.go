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

import "container/heap"

type segmentHeap []*segment

var _ heap.Interface = (*segmentHeap)(nil)

func (h *segmentHeap) Len() int {
	return len(*h)
}

func (h *segmentHeap) Less(i, j int) bool {
	return (*h)[i].sequenceNumber.LessThan((*h)[j].sequenceNumber)
}

func (h *segmentHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

func (h *segmentHeap) Push(x any) {
	*h = append(*h, x.(*segment))
}

func (h *segmentHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return x
}
