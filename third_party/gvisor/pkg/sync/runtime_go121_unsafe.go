// Copyright 2023 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

//go:build go1.21 && !go1.24

package sync

import (
	"unsafe"
)

const maptypeHasherOffset = unsafe.Offsetof(maptype{}.Hasher)
