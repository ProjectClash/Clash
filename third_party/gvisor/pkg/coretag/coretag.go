// Copyright 2022 The gVisor Authors.
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

package coretag

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/abi/linux"
)

func Enable() error {
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SCHED_CORE,
		unix.PR_SCHED_CORE_CREATE, 0, linux.PR_SCHED_CORE_SCOPE_THREAD_GROUP, 0, 0); errno != 0 {
		return fmt.Errorf("failed to core tag sentry: %w", errno)
	}
	return nil
}

func GetAllCoreTags(pid int) ([]uint64, error) {
	tagSet := make(map[uint64]struct{})
	tag, err := getCoreTag(pid)
	if err != nil {
		return nil, err
	}
	tagSet[tag] = struct{}{}

	tids, err := getTids(pid)
	if err != nil {
		return nil, err
	}
	for tid := range tids {
		tag, err := getCoreTag(tid)
		if err != nil {
			return nil, err
		}
		tagSet[tag] = struct{}{}
	}

	tags := make([]uint64, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags, nil
}

func getTids(pid int) (map[int]struct{}, error) {
	tids := make(map[int]struct{})
	path := "/proc/self/task"
	if pid != 0 {
		path = fmt.Sprintf("/proc/%d/task", pid)
	}
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		tid, err := strconv.Atoi(file.Name())
		if err != nil {
			return nil, err
		}
		tids[tid] = struct{}{}
	}

	return tids, nil
}
