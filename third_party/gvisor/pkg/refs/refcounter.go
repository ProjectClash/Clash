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

package refs

import (
	"bytes"
	"fmt"
	"runtime"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/context"
	"github.com/metacubex/gvisor/pkg/sync"
)

type RefCounter interface {
	IncRef()

	DecRef(ctx context.Context)
}

type TryRefCounter interface {
	RefCounter

	TryIncRef() bool
}

type LeakMode uint32

const (
	NoLeakChecking LeakMode = iota

	LeaksLogWarning

	LeaksPanic
)

func (l *LeakMode) Set(v string) error {
	switch v {
	case "disabled":
		*l = NoLeakChecking
	case "log-names":
		*l = LeaksLogWarning
	case "panic":
		*l = LeaksPanic
	default:
		return fmt.Errorf("invalid ref leak mode %q", v)
	}
	return nil
}

func (l *LeakMode) Get() any {
	return *l
}

func (l LeakMode) String() string {
	switch l {
	case NoLeakChecking:
		return "disabled"
	case LeaksLogWarning:
		return "log-names"
	case LeaksPanic:
		return "panic"
	default:
		panic(fmt.Sprintf("invalid ref leak mode %d", l))
	}
}

var leakMode atomicbitops.Uint32

func SetLeakMode(mode LeakMode) {
	leakMode.Store(uint32(mode))
}

func GetLeakMode() LeakMode {
	return LeakMode(leakMode.Load())
}

const maxStackFrames = 40

type fileLine struct {
	file string
	line int
}

type stackKey [maxStackFrames]fileLine

var stackCache = struct {
	sync.Mutex
	entries map[stackKey][]uintptr
}{entries: map[stackKey][]uintptr{}}

func makeStackKey(pcs []uintptr) stackKey {
	frames := runtime.CallersFrames(pcs)
	var key stackKey
	keySlice := key[:0]
	for {
		frame, more := frames.Next()
		keySlice = append(keySlice, fileLine{frame.File, frame.Line})

		if !more || len(keySlice) == len(key) {
			break
		}
	}
	return key
}

func RecordStack() []uintptr {
	pcs := make([]uintptr, maxStackFrames)
	n := runtime.Callers(1, pcs)
	if n == 0 {
		return nil
	}
	pcs = pcs[:n]
	key := makeStackKey(pcs)
	stackCache.Lock()
	v, ok := stackCache.entries[key]
	if !ok {
		v = append([]uintptr(nil), pcs...)
		stackCache.entries[key] = v
	}
	stackCache.Unlock()
	return v
}

func FormatStack(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	var trace bytes.Buffer
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&trace, "%s:%d: %s\n", frame.File, frame.Line, frame.Function)

		if !more {
			break
		}
	}
	return trace.String()
}

func OnExit() {
	if LeakMode(leakMode.Load()) != NoLeakChecking {
		runtime.GC()
	}
}
