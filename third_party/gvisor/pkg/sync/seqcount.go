// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

package sync

import (
	"sync/atomic"
)

type SeqCount struct {
	epoch uint32
}

type SeqCountEpoch uint32

func (s *SeqCount) BeginRead() SeqCountEpoch {
	if epoch := atomic.LoadUint32(&s.epoch); epoch&1 == 0 {
		return SeqCountEpoch(epoch)
	}
	return s.beginReadSlow()
}

func (s *SeqCount) beginReadSlow() SeqCountEpoch {
	i := 0
	for {
		if canSpin(i) {
			i++
			doSpin()
		} else {
			goyield()
		}
		if epoch := atomic.LoadUint32(&s.epoch); epoch&1 == 0 {
			return SeqCountEpoch(epoch)
		}
	}
}

func (s *SeqCount) ReadOk(epoch SeqCountEpoch) bool {
	MemoryFenceReads()
	return atomic.LoadUint32(&s.epoch) == uint32(epoch)
}

func (s *SeqCount) BeginWrite() {
	if epoch := atomic.AddUint32(&s.epoch, 1); epoch&1 == 0 {
		panic("SeqCount.BeginWrite during writer critical section")
	}
}

func (s *SeqCount) BeginWriteOk(epoch SeqCountEpoch) bool {
	return atomic.CompareAndSwapUint32(&s.epoch, uint32(epoch), uint32(epoch)+1)
}

func (s *SeqCount) EndWrite() {
	if epoch := atomic.AddUint32(&s.epoch, 1); epoch&1 != 0 {
		panic("SeqCount.EndWrite outside writer critical section")
	}
}
