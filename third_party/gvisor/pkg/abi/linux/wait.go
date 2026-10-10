// Copyright 2019 The gVisor Authors.
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

import (
	"fmt"
)

const (
	WNOHANG    = 0x00000001
	WUNTRACED  = 0x00000002
	WSTOPPED   = WUNTRACED
	WEXITED    = 0x00000004
	WCONTINUED = 0x00000008
	WNOWAIT    = 0x01000000
	WNOTHREAD  = 0x20000000
	WALL       = 0x40000000
	WCLONE     = 0x80000000
)

const (
	P_ALL   = 0x0
	P_PID   = 0x1
	P_PGID  = 0x2
	P_PIDFD = 0x3
)

type WaitStatus uint32

func WaitStatusExit(status int32) WaitStatus {
	return WaitStatus(uint32(status) << 8)
}

func WaitStatusTerminationSignal(sig Signal) WaitStatus {
	return WaitStatus(uint32(sig))
}

func WaitStatusStopped(code uint32) WaitStatus {
	return WaitStatus(code<<8 | 0x7f)
}

func WaitStatusContinued() WaitStatus {
	return WaitStatus(0xffff)
}

func (ws WaitStatus) WithCoreDump() WaitStatus {
	return ws | 0x80
}

func (ws WaitStatus) Exited() bool {
	return ws&0x7f == 0
}

func (ws WaitStatus) Signaled() bool {
	bits := ws & 0x7f
	return bits != 0 && bits != 0x7f
}

func (ws WaitStatus) CoreDumped() bool {
	return ws&0x80 != 0
}

func (ws WaitStatus) Stopped() bool {
	return ws&0xff == 0x7f
}

func (ws WaitStatus) Continued() bool {
	return ws == 0xffff
}

func (ws WaitStatus) ExitStatus() uint32 {
	return uint32((ws & 0xff00) >> 8)
}

func (ws WaitStatus) TerminationSignal() Signal {
	return Signal(ws & 0x7f)
}

func (ws WaitStatus) StopSignal() Signal {
	return Signal((ws & 0xff00) >> 8)
}

func (ws WaitStatus) PtraceEvent() uint32 {
	return uint32(ws >> 16)
}

func (ws WaitStatus) String() string {
	switch {
	case ws.Exited():
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	case ws.Signaled():
		if ws.CoreDumped() {
			return fmt.Sprintf("killed by signal %d (core dumped)", ws.TerminationSignal())
		}
		return fmt.Sprintf("killed by signal %d", ws.TerminationSignal())
	case ws.Stopped():
		if ev := ws.PtraceEvent(); ev != 0 {
			return fmt.Sprintf("stopped by signal %d (PTRACE_EVENT %d)", ws.StopSignal(), ev)
		}
		return fmt.Sprintf("stopped by signal %d", ws.StopSignal())
	case ws.Continued():
		return "continued"
	default:
		return fmt.Sprintf("unknown status %#x", uint32(ws))
	}
}
