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
	"encoding/binary"
	"github.com/metacubex/gvisor/pkg/common/structs"
)

const (
	XATTR_NAME_MAX = 255
	XATTR_SIZE_MAX = 65536
	XATTR_LIST_MAX = 65536

	XATTR_CREATE  = 1
	XATTR_REPLACE = 2

	XATTR_SECURITY_PREFIX     = "security."
	XATTR_SECURITY_PREFIX_LEN = len(XATTR_SECURITY_PREFIX)

	XATTR_SECURITY_CAPABILITY = XATTR_SECURITY_PREFIX + "capability"

	XATTR_SYSTEM_PREFIX     = "system."
	XATTR_SYSTEM_PREFIX_LEN = len(XATTR_SYSTEM_PREFIX)

	XATTR_TRUSTED_PREFIX     = "trusted."
	XATTR_TRUSTED_PREFIX_LEN = len(XATTR_TRUSTED_PREFIX)

	XATTR_USER_PREFIX     = "user."
	XATTR_USER_PREFIX_LEN = len(XATTR_USER_PREFIX)
)

const (
	XATTR_NAME_POSIX_ACL_ACCESS  = XATTR_SYSTEM_PREFIX + "posix_acl_access"
	XATTR_NAME_POSIX_ACL_DEFAULT = XATTR_SYSTEM_PREFIX + "posix_acl_default"

	POSIX_ACL_XATTR_VERSION = 2

	ACL_UNDEFINED_ID = 0xffffffff

	ACL_USER_OBJ  = 0x01
	ACL_USER      = 0x02
	ACL_GROUP_OBJ = 0x04
	ACL_GROUP     = 0x08
	ACL_MASK      = 0x10
	ACL_OTHER     = 0x20

	ACL_READ    = 0x04
	ACL_WRITE   = 0x02
	ACL_EXECUTE = 0x01
)

type PosixACLXattrEntry struct {
	_    structs.HostLayout
	Tag  uint16
	Perm uint16
	ID   uint32
}

func (a *PosixACLXattrEntry) SizeBytes() int {
	return 8
}

func (a *PosixACLXattrEntry) MarshalBytes(dst []byte) []byte {
	binary.LittleEndian.PutUint16(dst[0:], a.Tag)
	binary.LittleEndian.PutUint16(dst[2:], a.Perm)
	binary.LittleEndian.PutUint32(dst[4:], a.ID)

	return dst[8:]
}

func (a *PosixACLXattrEntry) UnmarshalBytes(src []byte) []byte {
	a.Tag = binary.LittleEndian.Uint16(src[0:])
	a.Perm = binary.LittleEndian.Uint16(src[2:])
	a.ID = binary.LittleEndian.Uint32(src[4:])

	return src[8:]
}

type PosixACLXattr struct {
	_ structs.HostLayout

	Version uint32

	Entries []PosixACLXattrEntry `hostlayout:"ignore"`
}

const posixACLXattrHeaderSize = 4

func (a *PosixACLXattr) SizeBytes() int {
	return posixACLXattrHeaderSize + len(a.Entries)*(*PosixACLXattrEntry)(nil).SizeBytes()
}

func (a *PosixACLXattr) MarshalBytes(dst []byte) []byte {
	binary.LittleEndian.PutUint32(dst, a.Version)

	dst = dst[posixACLXattrHeaderSize:]
	for _, entry := range a.Entries {
		dst = entry.MarshalBytes(dst)
	}

	return dst
}

func (a *PosixACLXattr) UnmarshalBytes(src []byte) []byte {
	a.Version = binary.LittleEndian.Uint32(src)

	src = src[posixACLXattrHeaderSize:]
	for len(src) >= (*PosixACLXattrEntry)(nil).SizeBytes() {
		var entry PosixACLXattrEntry
		src = entry.UnmarshalBytes(src)
		a.Entries = append(a.Entries, entry)
	}

	return src
}
