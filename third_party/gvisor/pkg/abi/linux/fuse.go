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

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"
	"time"

	"github.com/metacubex/gvisor/pkg/marshal/primitive"
)

type FUSEOpcode uint32

type FUSEOpID uint64

const FUSE_ROOT_ID = 1

const (
	FUSE_LOOKUP   FUSEOpcode = 1
	FUSE_FORGET              = 2
	FUSE_GETATTR             = 3
	FUSE_SETATTR             = 4
	FUSE_READLINK            = 5
	FUSE_SYMLINK             = 6
	_
	FUSE_MKNOD   = 8
	FUSE_MKDIR   = 9
	FUSE_UNLINK  = 10
	FUSE_RMDIR   = 11
	FUSE_RENAME  = 12
	FUSE_LINK    = 13
	FUSE_OPEN    = 14
	FUSE_READ    = 15
	FUSE_WRITE   = 16
	FUSE_STATFS  = 17
	FUSE_RELEASE = 18
	_
	FUSE_FSYNC        = 20
	FUSE_SETXATTR     = 21
	FUSE_GETXATTR     = 22
	FUSE_LISTXATTR    = 23
	FUSE_REMOVEXATTR  = 24
	FUSE_FLUSH        = 25
	FUSE_INIT         = 26
	FUSE_OPENDIR      = 27
	FUSE_READDIR      = 28
	FUSE_RELEASEDIR   = 29
	FUSE_FSYNCDIR     = 30
	FUSE_GETLK        = 31
	FUSE_SETLK        = 32
	FUSE_SETLKW       = 33
	FUSE_ACCESS       = 34
	FUSE_CREATE       = 35
	FUSE_INTERRUPT    = 36
	FUSE_BMAP         = 37
	FUSE_DESTROY      = 38
	FUSE_IOCTL        = 39
	FUSE_POLL         = 40
	FUSE_NOTIFY_REPLY = 41
	FUSE_BATCH_FORGET = 42
	FUSE_FALLOCATE    = 43
)

const (
	FUSE_MIN_READ_BUFFER uint32 = 8192
)

type FUSEHeaderIn struct {
	_ structs.HostLayout
	Len uint32

	Opcode FUSEOpcode

	Unique FUSEOpID

	NodeID uint64

	UID uint32

	GID uint32

	PID uint32

	_ uint32
}

var SizeOfFUSEHeaderIn = uint32((*FUSEHeaderIn)(nil).SizeBytes())

type FUSEHeaderOut struct {
	_ structs.HostLayout
	Len uint32

	Error int32

	Unique FUSEOpID
}

var SizeOfFUSEHeaderOut = uint32((*FUSEHeaderOut)(nil).SizeBytes())

const (
	FUSE_ASYNC_READ       = 1 << 0
	FUSE_POSIX_LOCKS      = 1 << 1
	FUSE_FILE_OPS         = 1 << 2
	FUSE_ATOMIC_O_TRUNC   = 1 << 3
	FUSE_EXPORT_SUPPORT   = 1 << 4
	FUSE_BIG_WRITES       = 1 << 5
	FUSE_DONT_MASK        = 1 << 6
	FUSE_SPLICE_WRITE     = 1 << 7
	FUSE_SPLICE_MOVE      = 1 << 8
	FUSE_SPLICE_READ      = 1 << 9
	FUSE_FLOCK_LOCKS      = 1 << 10
	FUSE_HAS_IOCTL_DIR    = 1 << 11
	FUSE_AUTO_INVAL_DATA  = 1 << 12
	FUSE_DO_READDIRPLUS   = 1 << 13
	FUSE_READDIRPLUS_AUTO = 1 << 14
	FUSE_ASYNC_DIO        = 1 << 15
	FUSE_WRITEBACK_CACHE  = 1 << 16
	FUSE_NO_OPEN_SUPPORT  = 1 << 17
	FUSE_MAX_PAGES        = 1 << 22
)

const (
	FUSE_KERNEL_VERSION       = 7
	FUSE_KERNEL_MINOR_VERSION = 31
)

const (
	FUSE_NAME_MAX        = 1024
	FUSE_PAGE_SIZE       = 4096
	FUSE_DIRENT_ALIGN    = 8
	FUSE_FSYNC_FDATASYNC = 1 << 0
)

type FUSEInitIn struct {
	_ structs.HostLayout
	Major uint32

	Minor uint32

	MaxReadahead uint32

	Flags uint32
}

type FUSEInitOut struct {
	_ structs.HostLayout
	Major uint32

	Minor uint32

	MaxReadahead uint32

	Flags uint32

	MaxBackground uint16

	CongestionThreshold uint16

	MaxWrite uint32

	TimeGran uint32

	MaxPages uint16

	_ uint16

	_ [8]uint32
}

type FUSEStatfsOut struct {
	_ structs.HostLayout
	Blocks uint64

	BlocksFree uint64

	BlocksAvailable uint64

	Files uint64

	FilesFree uint64

	BlockSize uint32

	NameLength uint32

	FragmentSize uint32

	_ uint32

	Spare [6]uint32
}

const FUSE_GETATTR_FH = (1 << 0)

type FUSEGetAttrIn struct {
	_ structs.HostLayout
	GetAttrFlags uint32

	_ uint32

	Fh uint64
}

type FUSEAttr struct {
	_ structs.HostLayout
	Ino uint64

	Size uint64

	Blocks uint64

	Atime uint64

	Mtime uint64

	Ctime uint64

	AtimeNsec uint32

	MtimeNsec uint32

	CtimeNsec uint32

	Mode uint32

	Nlink uint32

	UID uint32

	GID uint32

	Rdev uint32

	BlkSize uint32

	_ uint32
}

func (a FUSEAttr) ATimeNsec() int64 {
	return int64(a.Atime)*time.Second.Nanoseconds() + int64(a.AtimeNsec)
}

func (a FUSEAttr) MTimeNsec() int64 {
	return int64(a.Mtime)*time.Second.Nanoseconds() + int64(a.MtimeNsec)
}

func (a FUSEAttr) CTimeNsec() int64 {
	return int64(a.Ctime)*time.Second.Nanoseconds() + int64(a.CtimeNsec)
}

type FUSEAttrOut struct {
	_ structs.HostLayout
	AttrValid uint64

	AttrValidNsec uint32

	_ uint32

	Attr FUSEAttr
}

type FUSEEntryOut struct {
	_ structs.HostLayout
	NodeID uint64

	Generation uint64

	EntryValid uint64

	AttrValid uint64

	EntryValidNSec uint32

	AttrValidNSec uint32

	Attr FUSEAttr
}

type CString string

func (s *CString) MarshalBytes(buf []byte) []byte {
	copy(buf, *s)
	buf[len(*s)] = 0
	return buf[s.SizeBytes():]
}

func (s *CString) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, CString is never unmarshalled")
}

func (s *CString) SizeBytes() int {
	return len(*s) + 1
}

type FUSELookupIn struct {
	_ structs.HostLayout
	Name CString
}

func (r *FUSELookupIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSELookupIn is never unmarshalled")
}

func (r *FUSELookupIn) MarshalBytes(buf []byte) []byte {
	return r.Name.MarshalBytes(buf)
}

func (r *FUSELookupIn) SizeBytes() int {
	return r.Name.SizeBytes()
}

const MAX_NON_LFS = ((1 << 31) - 1)

const (
	FOPEN_DIRECT_IO = 1 << 0
	FOPEN_KEEP_CACHE = 1 << 1
	FOPEN_NONSEEKABLE = 1 << 2
	FOPEN_CACHE_DIR = 1 << 3
	FOPEN_STREAM = 1 << 4
	FOPEN_NOFLUSH = 1 << 5
)

type FUSEOpenIn struct {
	_ structs.HostLayout
	Flags uint32

	_ uint32
}

type FUSEOpenOut struct {
	_ structs.HostLayout
	Fh uint64

	OpenFlag uint32

	_ uint32
}

type FUSECreateOut struct {
	_ structs.HostLayout
	FUSEEntryOut
	FUSEOpenOut
}

const (
	FUSE_READ_LOCKOWNER = 1 << 1
)

type FUSEReadIn struct {
	_ structs.HostLayout
	Fh uint64

	Offset uint64

	Size uint32

	ReadFlags uint32

	LockOwner uint64

	Flags uint32

	_ uint32
}

type FUSEWriteIn struct {
	_ structs.HostLayout
	Fh uint64

	Offset uint64

	Size uint32

	WriteFlags uint32

	LockOwner uint64

	Flags uint32

	_ uint32
}

var SizeOfFUSEWriteIn = uint32((*FUSEWriteIn)(nil).SizeBytes())

type FUSEWritePayloadIn struct {
	_       structs.HostLayout
	Header  FUSEWriteIn
	Payload primitive.ByteSlice `hostlayout:"ignore"`
}

func (r *FUSEWritePayloadIn) SizeBytes() int {
	if r == nil {
		return (*FUSEWriteIn)(nil).SizeBytes()
	}
	return r.Header.SizeBytes() + r.Payload.SizeBytes()
}

func (r *FUSEWritePayloadIn) MarshalBytes(dst []byte) []byte {
	dst = r.Header.MarshalUnsafe(dst)
	dst = r.Payload.MarshalUnsafe(dst)
	return dst
}

func (r *FUSEWritePayloadIn) UnmarshalBytes(src []byte) []byte {
	panic("Unimplemented, FUSEWritePayloadIn is never unmarshalled")
}

type FUSEWriteOut struct {
	_ structs.HostLayout
	Size uint32

	_ uint32
}

type FUSEReleaseIn struct {
	_ structs.HostLayout
	Fh uint64

	Flags uint32

	ReleaseFlags uint32

	LockOwner uint64
}

type FUSECreateMeta struct {
	_ structs.HostLayout
	Flags uint32

	Mode uint32

	Umask uint32
	_     uint32
}

type FUSERenameIn struct {
	_       structs.HostLayout
	Newdir  primitive.Uint64
	Oldname CString
	Newname CString
}

func (r *FUSERenameIn) MarshalBytes(dst []byte) []byte {
	dst = r.Newdir.MarshalBytes(dst)
	dst = r.Oldname.MarshalBytes(dst)
	return r.Newname.MarshalBytes(dst)
}

func (r *FUSERenameIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSERmDirIn is never unmarshalled")
}

func (r *FUSERenameIn) SizeBytes() int {
	return r.Newdir.SizeBytes() + r.Oldname.SizeBytes() + r.Newname.SizeBytes()
}

type FUSECreateIn struct {
	_ structs.HostLayout
	CreateMeta FUSECreateMeta

	Name CString
}

func (r *FUSECreateIn) MarshalBytes(buf []byte) []byte {
	buf = r.CreateMeta.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

func (r *FUSECreateIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSECreateIn is never unmarshalled")
}

func (r *FUSECreateIn) SizeBytes() int {
	return r.CreateMeta.SizeBytes() + r.Name.SizeBytes()
}

type FUSEMknodMeta struct {
	_ structs.HostLayout
	Mode uint32

	Rdev uint32

	Umask uint32

	_ uint32
}

type FUSEMknodIn struct {
	_ structs.HostLayout
	MknodMeta FUSEMknodMeta
	Name CString
}

func (r *FUSEMknodIn) MarshalBytes(buf []byte) []byte {
	buf = r.MknodMeta.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

func (r *FUSEMknodIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEMknodIn is never unmarshalled")
}

func (r *FUSEMknodIn) SizeBytes() int {
	return r.MknodMeta.SizeBytes() + r.Name.SizeBytes()
}

type FUSESymlinkIn struct {
	_ structs.HostLayout
	Name CString

	Target CString
}

func (r *FUSESymlinkIn) MarshalBytes(buf []byte) []byte {
	buf = r.Name.MarshalBytes(buf)
	return r.Target.MarshalBytes(buf)
}

func (r *FUSESymlinkIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEMknodIn is never unmarshalled")
}

func (r *FUSESymlinkIn) SizeBytes() int {
	return r.Name.SizeBytes() + r.Target.SizeBytes()
}

type FUSELinkIn struct {
	_ structs.HostLayout
	OldNodeID primitive.Uint64
	Name CString
}

func (r *FUSELinkIn) MarshalBytes(buf []byte) []byte {
	buf = r.OldNodeID.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

func (r *FUSELinkIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSELinkIn is never unmarshalled")
}

func (r *FUSELinkIn) SizeBytes() int {
	return r.OldNodeID.SizeBytes() + r.Name.SizeBytes()
}

type FUSEEmptyIn struct {
	_ structs.HostLayout
}

func (r *FUSEEmptyIn) MarshalBytes(buf []byte) []byte {
	return buf
}

func (r *FUSEEmptyIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEEmptyIn is never unmarshalled")
}

func (r *FUSEEmptyIn) SizeBytes() int {
	return 0
}

type FUSEMkdirMeta struct {
	_ structs.HostLayout
	Mode uint32
	Umask uint32
}

type FUSEMkdirIn struct {
	_ structs.HostLayout
	MkdirMeta FUSEMkdirMeta
	Name CString
}

func (r *FUSEMkdirIn) MarshalBytes(buf []byte) []byte {
	buf = r.MkdirMeta.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

func (r *FUSEMkdirIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEMkdirIn is never unmarshalled")
}

func (r *FUSEMkdirIn) SizeBytes() int {
	return r.MkdirMeta.SizeBytes() + r.Name.SizeBytes()
}

type FUSERmDirIn struct {
	_ structs.HostLayout
	Name CString
}

func (r *FUSERmDirIn) MarshalBytes(buf []byte) []byte {
	return r.Name.MarshalBytes(buf)
}

func (r *FUSERmDirIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSERmDirIn is never unmarshalled")
}

func (r *FUSERmDirIn) SizeBytes() int {
	return r.Name.SizeBytes()
}

type FUSEGetXattrHdr struct {
	_    structs.HostLayout
	Size uint32
	_    uint32
}

type FUSEGetXattrIn struct {
	_    structs.HostLayout
	Hdr  FUSEGetXattrHdr
	Name CString
}

func (r *FUSEGetXattrIn) MarshalBytes(buf []byte) []byte {
	buf = r.Hdr.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

func (r *FUSEGetXattrIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEGetXattrIn is never unmarshalled")
}

func (r *FUSEGetXattrIn) SizeBytes() int {
	return r.Hdr.SizeBytes() + r.Name.SizeBytes()
}

type FUSEGetXattrOut struct {
	_    structs.HostLayout
	Size uint32
	_    uint32
}

type FUSESetXattrHdr struct {
	_     structs.HostLayout
	Size  uint32
	Flags uint32
}

type FUSESetXattrIn struct {
	_     structs.HostLayout
	Hdr   FUSESetXattrHdr
	Name  CString
	Value []byte `hostlayout:"ignore"`
}

func (r *FUSESetXattrIn) MarshalBytes(buf []byte) []byte {
	buf = r.Hdr.MarshalBytes(buf)
	buf = r.Name.MarshalBytes(buf)
	copy(buf, r.Value)
	return buf[len(r.Value):]
}

func (r *FUSESetXattrIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSESetXattrIn is never unmarshalled")
}

func (r *FUSESetXattrIn) SizeBytes() int {
	return r.Hdr.SizeBytes() + r.Name.SizeBytes() + len(r.Value)
}

type FUSEDirents struct {
	_       structs.HostLayout
	Dirents []*FUSEDirent `hostlayout:"ignore"`
}

type FUSEDirent struct {
	_ structs.HostLayout
	Meta FUSEDirentMeta
	Name string `hostlayout:"ignore"`
}

type FUSEDirentMeta struct {
	_ structs.HostLayout
	Ino uint64
	Off uint64
	NameLen uint32
	Type uint32
}

func (r *FUSEDirents) SizeBytes() int {
	var sizeBytes int
	for _, dirent := range r.Dirents {
		sizeBytes += dirent.SizeBytes()
	}

	return sizeBytes
}

func (r *FUSEDirents) MarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEDirents is never marshalled")
}

func (r *FUSEDirents) UnmarshalBytes(src []byte) []byte {
	for len(src) >= (*FUSEDirentMeta)(nil).SizeBytes() {
		var dirent FUSEDirent
		rem := dirent.UnmarshalBytes(src)
		if len(rem) == len(src) || len(dirent.Name) == 0 {
			break
		}
		if r.Dirents == nil {
			r.Dirents = make([]*FUSEDirent, 0)
		}
		r.Dirents = append(r.Dirents, &dirent)
		src = rem
	}
	return src
}

func (r *FUSEDirent) SizeBytes() int {
	dataSize := r.Meta.SizeBytes() + len(r.Name)

	return (dataSize + (FUSE_DIRENT_ALIGN - 1)) & ^(FUSE_DIRENT_ALIGN - 1)
}

func (r *FUSEDirent) MarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEDirent is never marshalled")
}

func (r *FUSEDirent) shiftNextDirent(buf []byte) []byte {
	nextOff := r.SizeBytes()
	if nextOff > len(buf) {
		return buf[len(buf):]
	}
	return buf[nextOff:]
}

func (r *FUSEDirent) UnmarshalBytes(src []byte) []byte {
	if len(src) < (*FUSEDirentMeta)(nil).SizeBytes() {
		return src
	}
	srcP := r.Meta.UnmarshalBytes(src)

	recLen := (r.Meta.SizeBytes() + int(r.Meta.NameLen) + (FUSE_DIRENT_ALIGN - 1)) & ^(FUSE_DIRENT_ALIGN - 1)
	if r.Meta.NameLen == 0 || r.Meta.NameLen > FUSE_NAME_MAX || recLen > len(src) {
		return src
	}

	buf := make([]byte, r.Meta.NameLen)
	name := primitive.ByteSlice(buf)
	name.UnmarshalBytes(srcP[:r.Meta.NameLen])
	r.Name = string(name)
	return r.shiftNextDirent(src)
}

const (
	FATTR_MODE      = (1 << 0)
	FATTR_UID       = (1 << 1)
	FATTR_GID       = (1 << 2)
	FATTR_SIZE      = (1 << 3)
	FATTR_ATIME     = (1 << 4)
	FATTR_MTIME     = (1 << 5)
	FATTR_FH        = (1 << 6)
	FATTR_ATIME_NOW = (1 << 7)
	FATTR_MTIME_NOW = (1 << 8)
	FATTR_LOCKOWNER = (1 << 9)
	FATTR_CTIME     = (1 << 10)
)

type FUSESetAttrIn struct {
	_ structs.HostLayout
	Valid uint32

	_ uint32

	Fh uint64

	Size uint64

	LockOwner uint64

	Atime uint64

	Mtime uint64

	Ctime uint64

	AtimeNsec uint32

	MtimeNsec uint32

	CtimeNsec uint32

	Mode uint32

	_ uint32

	UID uint32

	GID uint32

	_ uint32
}

type FUSEUnlinkIn struct {
	_ structs.HostLayout
	Name CString
}

func (r *FUSEUnlinkIn) MarshalBytes(buf []byte) []byte {
	return r.Name.MarshalBytes(buf)
}

func (r *FUSEUnlinkIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEUnlinkIn is never unmarshalled")
}

func (r *FUSEUnlinkIn) SizeBytes() int {
	return r.Name.SizeBytes()
}

type FUSEFsyncIn struct {
	_  structs.HostLayout
	Fh uint64

	FsyncFlags uint32

	_ uint32
}

type FUSEAccessIn struct {
	_    structs.HostLayout
	Mask uint32
	_ uint32
}

type FUSEFallocateIn struct {
	_      structs.HostLayout
	Fh     uint64
	Offset uint64
	Length uint64
	Mode   uint32
	_ uint32
}

type FUSEFlushIn struct {
	_         structs.HostLayout
	Fh        uint64
	_         uint32
	_         uint32
	LockOwner uint64
}
