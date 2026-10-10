// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

package sync

import (
	"github.com/metacubex/gvisor/pkg/common"
	"sync"
)

type (
	Cond = sync.Cond

	Locker = sync.Locker

	Once = sync.Once

	Pool = sync.Pool

	WaitGroup = sync.WaitGroup

	Map = sync.Map
)

func NewCond(l Locker) *Cond {
	return sync.NewCond(l)
}

func OnceFunc(f func()) func() {
	return common.OnceFunc(f)
}

func OnceValue[T any](f func() T) func() T {
	return common.OnceValue(f)
}

func OnceValues[T1, T2 any](f func() (T1, T2)) func() (T1, T2) {
	return common.OnceValues(f)
}
