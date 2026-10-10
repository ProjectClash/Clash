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
	"math"

	"github.com/metacubex/gvisor/pkg/hostarch"
)

const (
	ANON_INODE_FS_MAGIC   = 0x09041934
	CGROUP_SUPER_MAGIC    = 0x27e0eb
	CGROUP2_SUPER_MAGIC   = 0x63677270
	DEVPTS_SUPER_MAGIC    = 0x00001cd1
	EXT_SUPER_MAGIC       = 0xef53
	FUSE_SUPER_MAGIC      = 0x65735546
	MQUEUE_MAGIC          = 0x19800202
	NSFS_MAGIC            = 0x6e736673
	OVERLAYFS_SUPER_MAGIC = 0x794c7630
	PIPEFS_MAGIC          = 0x50495045
	PROC_SUPER_MAGIC      = 0x9fa0
	RAMFS_MAGIC           = 0x09041934
	SOCKFS_MAGIC          = 0x534F434B
	SYSFS_MAGIC           = 0x62656572
	TMPFS_MAGIC           = 0x01021994
	V9FS_MAGIC            = 0x01021997
)

const (
	NAME_MAX = 255
	PATH_MAX = 4096
)

const (
	ST_RDONLY      = 0x0001
	ST_NOSUID      = 0x0002
	ST_NODEV       = 0x0004
	ST_NOEXEC      = 0x0008
	ST_SYNCHRONOUS = 0x0010
	ST_VALID       = 0x0020
	ST_MANDLOCK    = 0x0040
	ST_NOATIME     = 0x0400
	ST_NODIRATIME  = 0x0800
	ST_RELATIME    = 0x1000
	ST_NOSYMFOLLOW = 0x2000
)

type Statfs struct {
	_ structs.HostLayout
	Type uint64

	BlockSize int64

	Blocks uint64

	BlocksFree uint64

	BlocksAvailable uint64

	Files uint64

	FilesFree uint64

	FSID [2]int32

	NameLength uint64

	FragmentSize int64

	Flags uint64

	Spare [4]uint64
}

const (
	SEEK_SET  = 0
	SEEK_CUR  = 1
	SEEK_END  = 2
	SEEK_DATA = 3
	SEEK_HOLE = 4
)

const (
	SYNC_FILE_RANGE_WAIT_BEFORE = 1
	SYNC_FILE_RANGE_WRITE       = 2
	SYNC_FILE_RANGE_WAIT_AFTER  = 4
)

const (
	RENAME_NOREPLACE = (1 << 0)
	RENAME_EXCHANGE  = (1 << 1)
	RENAME_WHITEOUT  = (1 << 2)
)

const (
	WHITEOUT_MODE = 0
	WHITEOUT_DEV  = 0
)

var MAX_RW_COUNT = int(hostarch.PageRoundDown(uint32(math.MaxInt32)))
