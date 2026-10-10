// Copyright 2020 The gVisor Authors.
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
	"fmt"

	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/sync"
)

var (
	liveObjects   map[CheckedObject]struct{}
	liveObjectsMu sync.Mutex
)

type CheckedObject interface {
	RefType() string

	LeakMessage() string

	LogRefs() bool
}

func init() {
	liveObjects = make(map[CheckedObject]struct{})
}

func LeakCheckEnabled() bool {
	mode := GetLeakMode()
	return mode != NoLeakChecking
}

func leakCheckPanicEnabled() bool {
	return GetLeakMode() == LeaksPanic
}

func Register(obj CheckedObject) {
	if LeakCheckEnabled() {
		liveObjectsMu.Lock()
		if _, ok := liveObjects[obj]; ok {
			panic(fmt.Sprintf("Unexpected entry in leak checking map: reference %p already added", obj))
		}
		liveObjects[obj] = struct{}{}
		liveObjectsMu.Unlock()
		if LeakCheckEnabled() && obj.LogRefs() {
			logEvent(obj, "registered")
		}
	}
}

func Unregister(obj CheckedObject) {
	if LeakCheckEnabled() {
		liveObjectsMu.Lock()
		defer liveObjectsMu.Unlock()
		if _, ok := liveObjects[obj]; !ok {
			panic(fmt.Sprintf("Expected to find entry in leak checking map for reference %p", obj))
		}
		delete(liveObjects, obj)
		if LeakCheckEnabled() && obj.LogRefs() {
			logEvent(obj, "unregistered")
		}
	}
}

func LogIncRef(obj CheckedObject, refs int64) {
	if LeakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("IncRef to %d", refs))
	}
}

func LogTryIncRef(obj CheckedObject, refs int64) {
	if LeakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("TryIncRef to %d", refs))
	}
}

func LogDecRef(obj CheckedObject, refs int64) {
	if LeakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("DecRef to %d", refs))
	}
}

func logEvent(obj CheckedObject, msg string) {
	log.Infof("[%s %p] %s:\n%s", obj.RefType(), obj, msg, FormatStack(RecordStack()))
}

var checkOnce sync.Once

func DoLeakCheck() {
	if LeakCheckEnabled() {
		checkOnce.Do(doLeakCheck)
	}
}

func DoRepeatedLeakCheck() {
	if LeakCheckEnabled() {
		doLeakCheck()
	}
}

type leakCheckDisabled interface {
	LeakCheckDisabled() bool
}

var CleanupSync sync.WaitGroup

func doLeakCheck() {
	CleanupSync.Wait()
	liveObjectsMu.Lock()
	defer liveObjectsMu.Unlock()
	leaked := len(liveObjects)
	if leaked > 0 {
		n := 0
		msg := fmt.Sprintf("Leak checking detected %d leaked objects:\n", leaked)
		for obj := range liveObjects {
			skip := false
			if o, ok := obj.(leakCheckDisabled); ok {
				skip = o.LeakCheckDisabled()
			}
			if skip {
				log.Debugf("%s", obj.LeakMessage())
				continue
			}
			msg += obj.LeakMessage() + "\n"
			n++
		}
		if n == 0 {
			return
		}
		if leakCheckPanicEnabled() {
			panic(msg)
		}
		log.Warningf("%s", msg)
	}
}
