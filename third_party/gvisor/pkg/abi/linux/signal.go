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

import (
	"github.com/metacubex/gvisor/pkg/common/structs"

	"github.com/metacubex/gvisor/pkg/bits"
	"github.com/metacubex/gvisor/pkg/hostarch"
)

const (
	SignalMaximum = 64

	FirstStdSignal = 1

	LastStdSignal = 31

	FirstRTSignal = 32

	LastRTSignal = 64

	NumStdSignals = LastStdSignal - FirstStdSignal + 1

	NumRTSignals = LastRTSignal - FirstRTSignal + 1
)

type Signal int

func (s Signal) IsValid() bool {
	return s > 0 && s <= SignalMaximum
}

func (s Signal) IsStandard() bool {
	return s <= LastStdSignal
}

func (s Signal) IsRealtime() bool {
	return s >= FirstRTSignal
}

func (s Signal) Index() int {
	return int(s - 1)
}

const (
	SIGABRT   = Signal(6)
	SIGALRM   = Signal(14)
	SIGBUS    = Signal(7)
	SIGCHLD   = Signal(17)
	SIGCLD    = Signal(17)
	SIGCONT   = Signal(18)
	SIGFPE    = Signal(8)
	SIGHUP    = Signal(1)
	SIGILL    = Signal(4)
	SIGINT    = Signal(2)
	SIGIO     = Signal(29)
	SIGIOT    = Signal(6)
	SIGKILL   = Signal(9)
	SIGPIPE   = Signal(13)
	SIGPOLL   = Signal(29)
	SIGPROF   = Signal(27)
	SIGPWR    = Signal(30)
	SIGQUIT   = Signal(3)
	SIGSEGV   = Signal(11)
	SIGSTKFLT = Signal(16)
	SIGSTOP   = Signal(19)
	SIGSYS    = Signal(31)
	SIGTERM   = Signal(15)
	SIGTRAP   = Signal(5)
	SIGTSTP   = Signal(20)
	SIGTTIN   = Signal(21)
	SIGTTOU   = Signal(22)
	SIGUNUSED = Signal(31)
	SIGURG    = Signal(23)
	SIGUSR1   = Signal(10)
	SIGUSR2   = Signal(12)
	SIGVTALRM = Signal(26)
	SIGWINCH  = Signal(28)
	SIGXCPU   = Signal(24)
	SIGXFSZ   = Signal(25)
)

type SignalSet uint64

const SignalSetSize = 8

func MakeSignalSet(sigs ...Signal) SignalSet {
	indices := make([]int, len(sigs))
	for i, sig := range sigs {
		indices[i] = sig.Index()
	}
	return bits.Mask[SignalSet](indices...)
}

func SignalSetOf(sig Signal) SignalSet {
	return bits.MaskOf[SignalSet](sig.Index())
}

func ForEachSignal(mask SignalSet, f func(sig Signal)) {
	bits.ForEachSetBit64(uint64(mask), func(i int) {
		f(Signal(i + 1))
	})
}

const (
	SIG_BLOCK = 0

	SIG_UNBLOCK = 1

	SIG_SETMASK = 2
)

const (
	SIG_DFL = 0

	SIG_IGN = 1
)

const (
	SA_NOCLDSTOP = 0x00000001
	SA_NOCLDWAIT = 0x00000002
	SA_SIGINFO   = 0x00000004
	SA_RESTORER  = 0x04000000
	SA_ONSTACK   = 0x08000000
	SA_RESTART   = 0x10000000
	SA_NODEFER   = 0x40000000
	SA_RESETHAND = 0x80000000
	SA_NOMASK    = SA_NODEFER
	SA_ONESHOT   = SA_RESETHAND
)

const (
	SS_ONSTACK = 1
	SS_DISABLE = 2
)

const (
	SI_POLL = 2 << 16

	POLL_IN = SI_POLL | 1

	POLL_OUT = SI_POLL | 2

	POLL_MSG = SI_POLL | 3

	POLL_ERR = SI_POLL | 4

	POLL_PRI = SI_POLL | 5

	POLL_HUP = SI_POLL | 6
)

const (
	SI_USER = 0

	SI_KERNEL = 0x80

	SI_QUEUE = -1

	SI_TIMER = -2

	SI_MESGQ = -3

	SI_ASYNCIO = -4

	SI_SIGIO = -5

	SI_TKILL = -6

	SI_DETHREAD = -7

	SI_ASYNCNL = -60
)

const (
	CLD_EXITED = 1

	CLD_KILLED = 2

	CLD_DUMPED = 3

	CLD_TRAPPED = 4

	CLD_STOPPED = 5

	CLD_CONTINUED = 6
)

const (
	SYS_SECCOMP = 1
)

const (
	SIGEV_SIGNAL    = 0
	SIGEV_NONE      = 1
	SIGEV_THREAD    = 2
	SIGEV_THREAD_ID = 4
)

const (
	TRAP_BRKPT  = 1
	TRAP_TRACE  = 2
	TRAP_BRANCH = 3
	TRAP_HWBKPT = 4
)

type Sigevent struct {
	_      structs.HostLayout
	Value  uint64
	Signo  int32
	Notify int32

	Tid         int32
	UnRemainder [44]byte
}

type SigAction struct {
	_        structs.HostLayout
	Handler  uint64
	Flags    uint64
	Restorer uint64
	Mask     SignalSet
}

type SignalStack struct {
	_     structs.HostLayout
	Addr  uint64
	Flags uint32
	_     uint32
	Size  uint64
}

func (s *SignalStack) Contains(sp hostarch.Addr) bool {
	return hostarch.Addr(s.Addr) < sp && sp <= hostarch.Addr(s.Addr+s.Size)
}

func (s *SignalStack) Top() hostarch.Addr {
	return hostarch.Addr(s.Addr + s.Size)
}

func (s *SignalStack) IsEnabled() bool {
	return s.Flags&SS_DISABLE == 0
}

type SignalInfo struct {
	_     structs.HostLayout
	Signo int32
	Errno int32
	Code  int32
	_     uint32

	Fields [128 - 16]byte
}

func (s *SignalInfo) FixSignalCodeForUser() {
	if s.Code > 0 {
		s.Code &= 0x0000ffff
	}
}

func (s *SignalInfo) PID() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[0:4]))
}

func (s *SignalInfo) SetPID(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[0:4], uint32(val))
}

func (s *SignalInfo) UID() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[4:8]))
}

func (s *SignalInfo) SetUID(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[4:8], uint32(val))
}

func (s *SignalInfo) Sigval() uint64 {
	return hostarch.ByteOrder.Uint64(s.Fields[8:16])
}

func (s *SignalInfo) SetSigval(val uint64) {
	hostarch.ByteOrder.PutUint64(s.Fields[8:16], val)
}

func (s *SignalInfo) TimerID() TimerID {
	return TimerID(hostarch.ByteOrder.Uint32(s.Fields[0:4]))
}

func (s *SignalInfo) SetTimerID(val TimerID) {
	hostarch.ByteOrder.PutUint32(s.Fields[0:4], uint32(val))
}

func (s *SignalInfo) Overrun() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[4:8]))
}

func (s *SignalInfo) SetOverrun(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[4:8], uint32(val))
}

func (s *SignalInfo) Addr() uint64 {
	return hostarch.ByteOrder.Uint64(s.Fields[0:8])
}

func (s *SignalInfo) SetAddr(val uint64) {
	hostarch.ByteOrder.PutUint64(s.Fields[0:8], val)
}

func (s *SignalInfo) Status() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[8:12]))
}

func (s *SignalInfo) SetStatus(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[8:12], uint32(val))
}

func (s *SignalInfo) CallAddr() uint64 {
	return hostarch.ByteOrder.Uint64(s.Fields[0:8])
}

func (s *SignalInfo) SetCallAddr(val uint64) {
	hostarch.ByteOrder.PutUint64(s.Fields[0:8], val)
}

func (s *SignalInfo) Syscall() int32 {
	return int32(hostarch.ByteOrder.Uint32(s.Fields[8:12]))
}

func (s *SignalInfo) SetSyscall(val int32) {
	hostarch.ByteOrder.PutUint32(s.Fields[8:12], uint32(val))
}

func (s *SignalInfo) Arch() uint32 {
	return hostarch.ByteOrder.Uint32(s.Fields[12:16])
}

func (s *SignalInfo) SetArch(val uint32) {
	hostarch.ByteOrder.PutUint32(s.Fields[12:16], val)
}

func (s *SignalInfo) Band() int64 {
	return int64(hostarch.ByteOrder.Uint64(s.Fields[0:8]))
}

func (s *SignalInfo) SetBand(val int64) {
	hostarch.ByteOrder.PutUint64(s.Fields[0:8], uint64(val))
}

func (s *SignalInfo) FD() uint32 {
	return hostarch.ByteOrder.Uint32(s.Fields[8:12])
}

func (s *SignalInfo) SetFD(val uint32) {
	hostarch.ByteOrder.PutUint32(s.Fields[8:12], val)
}
