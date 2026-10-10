// Copyright 2025 The gVisor Authors.
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

package gomaxprocs

import (
	"runtime"

	"github.com/metacubex/gvisor/pkg/log"
)

var (
	mu gomaxprocsMutex
	base int
	temp int
)

func SetBase(n int) {
	if n < 1 {
		log.Traceback("Invalid base GOMAXPROCS: %d", n)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	oldBase := base
	base = n
	updateRuntime(oldBase, temp)
}

func Add(n int) {
	mu.Lock()
	defer mu.Unlock()
	t := temp + n
	if t < 0 {
		log.Traceback("gomaxprocs.Add(%d) would cause temp to become %d", n, t)
		return
	}
	oldTemp := temp
	temp = t
	if base != 0 {
		updateRuntime(base, oldTemp)
	}
}

func updateRuntime(oldBase, oldTemp int) {
	n := base + temp
	log.Debugf("Setting GOMAXPROCS to %d", n)
	got := runtime.GOMAXPROCS(n)
	if want := oldBase + oldTemp; oldBase != 0 && got != want {
		log.Warningf("Previous GOMAXPROCS was %d, expected %d = %d + %d", got, want, oldBase, oldTemp)
	}
}
