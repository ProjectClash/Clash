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

package linux

const (
	PR_SET_PDEATHSIG = 1

	PR_GET_PDEATHSIG = 2

	PR_GET_DUMPABLE = 3

	PR_SET_DUMPABLE = 4

	PR_GET_KEEPCAPS = 7

	PR_SET_KEEPCAPS = 8

	PR_GET_SECUREBITS = 27

	PR_SET_SECUREBITS = 28

	PR_GET_TIMING = 13

	PR_SET_TIMING = 14

	PR_SET_NAME = 15

	PR_GET_NAME = 16

	PR_GET_SECCOMP = 21

	PR_SET_SECCOMP = 22

	PR_CAPBSET_READ = 23

	PR_CAPBSET_DROP = 24

	PR_GET_TSC = 25

	PR_SET_TSC = 26

	PR_SET_TIMERSLACK = 29

	PR_GET_TIMERSLACK = 30

	PR_TASK_PERF_EVENTS_DISABLE = 31

	PR_TASK_PERF_EVENTS_ENABLE = 32

	PR_MCE_KILL = 33

	PR_MCE_KILL_GET = 34

	PR_SET_MM = 35

	PR_SET_MM_START_CODE  = 1
	PR_SET_MM_END_CODE    = 2
	PR_SET_MM_START_DATA  = 3
	PR_SET_MM_END_DATA    = 4
	PR_SET_MM_START_STACK = 5
	PR_SET_MM_START_BRK   = 6
	PR_SET_MM_BRK         = 7
	PR_SET_MM_ARG_START   = 8
	PR_SET_MM_ARG_END     = 9
	PR_SET_MM_ENV_START   = 10
	PR_SET_MM_ENV_END     = 11
	PR_SET_MM_AUXV        = 12
	PR_SET_MM_EXE_FILE = 13
	PR_SET_MM_MAP      = 14
	PR_SET_MM_MAP_SIZE = 15

	PR_SET_CHILD_SUBREAPER = 36

	PR_GET_CHILD_SUBREAPER = 37

	PR_SET_NO_NEW_PRIVS = 38

	PR_GET_NO_NEW_PRIVS = 39

	PR_GET_TID_ADDRESS = 40

	PR_SET_THP_DISABLE = 41

	PR_GET_THP_DISABLE = 42

	PR_MPX_ENABLE_MANAGEMENT = 43

	PR_MPX_DISABLE_MANAGEMENT = 44

	PR_SCHED_CORE_SCOPE_THREAD       = 0
	PR_SCHED_CORE_SCOPE_THREAD_GROUP = 1

	PR_SET_VMA           = 0x53564d41
	PR_SET_VMA_ANON_NAME = 0
	ANON_VMA_NAME_MAX_LEN = 80

	PR_SET_PTRACER     = 0x59616d61
	PR_SET_PTRACER_ANY = -1

	PR_SET_TAGGED_ADDR_CTRL = 55
	PR_GET_TAGGED_ADDR_CTRL = 56
	PR_TAGGED_ADDR_ENABLE   = (1 << 0)

	PR_CAP_AMBIENT = 47

	PR_CAP_AMBIENT_IS_SET    = 1
	PR_CAP_AMBIENT_RAISE     = 2
	PR_CAP_AMBIENT_LOWER     = 3
	PR_CAP_AMBIENT_CLEAR_ALL = 4

	SECBIT_KEEP_CAPS = 1 << 4
)

const (
	ARCH_SET_GS    = 0x1001
	ARCH_SET_FS    = 0x1002
	ARCH_GET_FS    = 0x1003
	ARCH_GET_GS    = 0x1004
	ARCH_SET_CPUID = 0x1012
)

const (
	SUID_DUMP_DISABLE = 0
	SUID_DUMP_USER    = 1
	SUID_DUMP_ROOT    = 2
)
