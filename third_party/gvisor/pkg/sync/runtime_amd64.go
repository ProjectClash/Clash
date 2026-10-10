// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

//go:build amd64

package sync

import (
	"sync/atomic"
)

const supportsWakeSuppression = true

func addrOfSpinning() *int32

var nmspinning = addrOfSpinning()

//go:nosplit
func preGoReadyWakeSuppression() {
	atomic.AddInt32(nmspinning, 1)
}

//go:nosplit
func postGoReadyWakeSuppression() {
	atomic.AddInt32(nmspinning, -1)
}
