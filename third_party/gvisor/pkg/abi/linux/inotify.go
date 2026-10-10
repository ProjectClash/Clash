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
	IN_ACCESS = 0x00000001
	IN_MODIFY = 0x00000002
	IN_ATTRIB = 0x00000004
	IN_CLOSE_WRITE = 0x00000008
	IN_CLOSE_NOWRITE = 0x00000010
	IN_OPEN = 0x00000020
	IN_MOVED_FROM = 0x00000040
	IN_MOVED_TO = 0x00000080
	IN_CREATE = 0x00000100
	IN_DELETE = 0x00000200
	IN_DELETE_SELF = 0x00000400
	IN_MOVE_SELF = 0x00000800
	IN_ALL_EVENTS = 0x00000fff
)

const (
	IN_UNMOUNT = 0x00002000
	IN_Q_OVERFLOW = 0x00004000
	IN_IGNORED = 0x00008000
	IN_ISDIR = 0x40000000
)

const (
	IN_ONLYDIR = 0x01000000
	IN_DONT_FOLLOW = 0x02000000
	IN_EXCL_UNLINK = 0x04000000
	IN_MASK_ADD = 0x20000000
	IN_ONESHOT = 0x80000000
)

const (
	IN_CLOEXEC = 0x00080000
	IN_NONBLOCK = 0x00000800
)

const ALL_INOTIFY_BITS = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
	IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE |
	IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT | IN_Q_OVERFLOW |
	IN_IGNORED | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_ADD |
	IN_ISDIR | IN_ONESHOT
