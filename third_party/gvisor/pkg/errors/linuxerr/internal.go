// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"),;
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

package linuxerr

import (
	"github.com/metacubex/gvisor/pkg/abi/linux/errno"
	"github.com/metacubex/gvisor/pkg/errors"
)

var (
	ErrWouldBlock = errors.New(errno.EWOULDBLOCK, "request would block")

	ErrInterrupted = errors.New(errno.EINTR, "request was interrupted")

	ErrExceedsFileSizeLimit = errors.New(errno.E2BIG, "exceeds file size limit")
)

var errorMap = map[error]*errors.Error{
	ErrWouldBlock:           EWOULDBLOCK,
	ErrInterrupted:          EINTR,
	ErrExceedsFileSizeLimit: EFBIG,
}

var errorUnwrappers = []func(error) (*errors.Error, bool){}

func AddErrorUnwrapper(unwrap func(e error) (*errors.Error, bool)) {
	errorUnwrappers = append(errorUnwrappers, unwrap)
}

func TranslateError(from error) (*errors.Error, bool) {
	if err, ok := errorMap[from]; ok {
		return err, true
	}
	for _, unwrap := range errorUnwrappers {
		if err, ok := unwrap(from); ok {
			return err, true
		}
	}
	return nil, false
}

var (
	ERESTARTSYS = errors.New(errno.ERESTARTSYS, "to be restarted if SA_RESTART is set")

	ERESTARTNOINTR = errors.New(errno.ERESTARTNOINTR, "to be restarted")

	ERESTARTNOHAND = errors.New(errno.ERESTARTNOHAND, "to be restarted if no handler")

	ERESTART_RESTARTBLOCK = errors.New(errno.ERESTART_RESTARTBLOCK, "interrupted by signal")
)

var restartMap = map[int]*errors.Error{
	-int(errno.ERESTARTSYS):           ERESTARTSYS,
	-int(errno.ERESTARTNOINTR):        ERESTARTNOINTR,
	-int(errno.ERESTARTNOHAND):        ERESTARTNOHAND,
	-int(errno.ERESTART_RESTARTBLOCK): ERESTART_RESTARTBLOCK,
}

func IsRestartError(err error) bool {
	switch err {
	case ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK:
		return true
	default:
		return false
	}
}

func SyscallRestartErrorFromReturn(rv uintptr) (*errors.Error, bool) {
	err, ok := restartMap[int(rv)]
	return err, ok
}

func ConvertIntr(err, intr error) error {
	if Equals(ErrInterrupted, err) {
		return intr
	}
	return err
}
