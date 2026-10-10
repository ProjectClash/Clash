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
)

const (
	AT_NULL = 0

	AT_IGNORE = 1

	AT_EXECFD = 2

	AT_PHDR = 3

	AT_PHENT = 4

	AT_PHNUM = 5

	AT_PAGESZ = 6

	AT_BASE = 7

	AT_FLAGS = 8

	AT_ENTRY = 9

	AT_NOTELF = 10

	AT_UID = 11

	AT_EUID = 12

	AT_GID = 13

	AT_EGID = 14

	AT_PLATFORM = 15

	AT_HWCAP = 16

	AT_CLKTCK = 17

	AT_SECURE = 23

	AT_BASE_PLATFORM = 24

	AT_RANDOM = 25

	AT_HWCAP2 = 26

	AT_EXECFN = 31

	AT_SYSINFO_EHDR = 33
)

const (
	NT_PRSTATUS = 0x1

	NT_PRFPREG = 0x2

	NT_X86_XSTATE = 0x202

	NT_ARM_TLS = 0x401
)

type ElfHeader64 struct {
	_         structs.HostLayout
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type ElfSection64 struct {
	_         structs.HostLayout
	Name      uint32
	Type      uint32
	Flags     uint64
	Addr      uint64
	Off       uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

type ElfProg64 struct {
	_      structs.HostLayout
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}
