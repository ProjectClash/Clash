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

package fsutil

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/syserr"
)

var UnixDirentMaxSize = int(unsafe.Sizeof(unix.Dirent{}))

func Utimensat(dirFd int, name string, times [2]unix.Timespec, flags int) error {
	var namePtr unsafe.Pointer
	if name != "" {
		nameBytes, err := unix.BytePtrFromString(name)
		if err != nil {
			return err
		}
		namePtr = unsafe.Pointer(nameBytes)
	}

	timesPtr := unsafe.Pointer(&times[0])

	if _, _, errno := unix.Syscall6(
		unix.SYS_UTIMENSAT,
		uintptr(dirFd),
		uintptr(namePtr),
		uintptr(timesPtr),
		uintptr(flags),
		0,
		0); errno != 0 {

		return syserr.FromHost(errno).ToError()
	}
	return nil
}

func RenameAt2(oldDirFD int, oldName string, newDirFD int, newName string, flags uint32) error {
	var oldNamePtr unsafe.Pointer
	if oldName != "" {
		nameBytes, err := unix.BytePtrFromString(oldName)
		if err != nil {
			return err
		}
		oldNamePtr = unsafe.Pointer(nameBytes)
	}
	var newNamePtr unsafe.Pointer
	if newName != "" {
		nameBytes, err := unix.BytePtrFromString(newName)
		if err != nil {
			return err
		}
		newNamePtr = unsafe.Pointer(nameBytes)
	}

	if _, _, errno := unix.Syscall6(
		unix.SYS_RENAMEAT2,
		uintptr(oldDirFD),
		uintptr(oldNamePtr),
		uintptr(newDirFD),
		uintptr(newNamePtr),
		uintptr(flags),
		0); errno != 0 {

		return syserr.FromHost(errno).ToError()
	}
	return nil
}

func ParseDirents(buf []byte, handleDirent DirentHandler) {
	for len(buf) > 0 {
		dirent := *(*unix.Dirent)(unsafe.Pointer(&buf[0]))

		nameBuf := buf[unsafe.Offsetof(dirent.Name):dirent.Reclen]
		nameLen := bytes.IndexByte(nameBuf, 0)
		name := string(nameBuf[:nameLen])

		buf = buf[dirent.Reclen:]

		if name == "." || name == ".." {
			continue
		}

		handleDirent(dirent.Ino, dirent.Off, dirent.Type, name, dirent.Reclen)
	}
}
