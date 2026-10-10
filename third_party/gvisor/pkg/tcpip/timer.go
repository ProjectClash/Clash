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

package tcpip

import (
	"time"

	"github.com/metacubex/gvisor/pkg/sync"
)

type jobInstance struct {
	timer Timer `state:"nosave"`

	earlyReturn *bool
}

func (j *jobInstance) stop() {
	if j.timer != nil {
		j.timer.Stop()
		*j.earlyReturn = true
	}
}

type Job struct {
	_ sync.NoCopy

	clock Clock

	instance jobInstance

	locker sync.Locker `state:"nosave"`

	fn func() `state:"nosave"`
}

func (j *Job) Cancel() {
	j.instance.stop()

	j.instance = jobInstance{}
}

func (j *Job) Schedule(d time.Duration) {
	earlyReturn := false

	locker := j.locker
	j.instance = jobInstance{
		timer: j.clock.AfterFunc(d, func() {
			locker.Lock()
			defer locker.Unlock()

			if earlyReturn {
				earlyReturn = false
				return
			}

			j.fn()
		}),
		earlyReturn: &earlyReturn,
	}
}

func NewJob(c Clock, l sync.Locker, f func()) *Job {
	return &Job{
		clock:  c,
		locker: l,
		fn:     f,
	}
}
