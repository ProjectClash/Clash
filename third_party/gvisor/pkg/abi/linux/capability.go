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
	"strings"
)

type Capability int

const (
	CAP_CHOWN              = Capability(0)
	CAP_DAC_OVERRIDE       = Capability(1)
	CAP_DAC_READ_SEARCH    = Capability(2)
	CAP_FOWNER             = Capability(3)
	CAP_FSETID             = Capability(4)
	CAP_KILL               = Capability(5)
	CAP_SETGID             = Capability(6)
	CAP_SETUID             = Capability(7)
	CAP_SETPCAP            = Capability(8)
	CAP_LINUX_IMMUTABLE    = Capability(9)
	CAP_NET_BIND_SERVICE   = Capability(10)
	CAP_NET_BROADCAST      = Capability(11)
	CAP_NET_ADMIN          = Capability(12)
	CAP_NET_RAW            = Capability(13)
	CAP_IPC_LOCK           = Capability(14)
	CAP_IPC_OWNER          = Capability(15)
	CAP_SYS_MODULE         = Capability(16)
	CAP_SYS_RAWIO          = Capability(17)
	CAP_SYS_CHROOT         = Capability(18)
	CAP_SYS_PTRACE         = Capability(19)
	CAP_SYS_PACCT          = Capability(20)
	CAP_SYS_ADMIN          = Capability(21)
	CAP_SYS_BOOT           = Capability(22)
	CAP_SYS_NICE           = Capability(23)
	CAP_SYS_RESOURCE       = Capability(24)
	CAP_SYS_TIME           = Capability(25)
	CAP_SYS_TTY_CONFIG     = Capability(26)
	CAP_MKNOD              = Capability(27)
	CAP_LEASE              = Capability(28)
	CAP_AUDIT_WRITE        = Capability(29)
	CAP_AUDIT_CONTROL      = Capability(30)
	CAP_SETFCAP            = Capability(31)
	CAP_MAC_OVERRIDE       = Capability(32)
	CAP_MAC_ADMIN          = Capability(33)
	CAP_SYSLOG             = Capability(34)
	CAP_WAKE_ALARM         = Capability(35)
	CAP_BLOCK_SUSPEND      = Capability(36)
	CAP_AUDIT_READ         = Capability(37)
	CAP_PERFMON            = Capability(38)
	CAP_BPF                = Capability(39)
	CAP_CHECKPOINT_RESTORE = Capability(40)

	CAP_LAST_CAP = CAP_CHECKPOINT_RESTORE
)

func (cp Capability) Ok() bool {
	return cp >= 0 && cp <= CAP_LAST_CAP
}

func (cp Capability) String() string {
	switch cp {
	case CAP_CHOWN:
		return "CAP_CHOWN"
	case CAP_DAC_OVERRIDE:
		return "CAP_DAC_OVERRIDE"
	case CAP_DAC_READ_SEARCH:
		return "CAP_DAC_READ_SEARCH"
	case CAP_FOWNER:
		return "CAP_FOWNER"
	case CAP_FSETID:
		return "CAP_FSETID"
	case CAP_KILL:
		return "CAP_KILL"
	case CAP_SETGID:
		return "CAP_SETGID"
	case CAP_SETUID:
		return "CAP_SETUID"
	case CAP_SETPCAP:
		return "CAP_SETPCAP"
	case CAP_LINUX_IMMUTABLE:
		return "CAP_LINUX_IMMUTABLE"
	case CAP_NET_BIND_SERVICE:
		return "CAP_NET_BIND_SERVICE"
	case CAP_NET_BROADCAST:
		return "CAP_NET_BROADCAST"
	case CAP_NET_ADMIN:
		return "CAP_NET_ADMIN"
	case CAP_NET_RAW:
		return "CAP_NET_RAW"
	case CAP_IPC_LOCK:
		return "CAP_IPC_LOCK"
	case CAP_IPC_OWNER:
		return "CAP_IPC_OWNER"
	case CAP_SYS_MODULE:
		return "CAP_SYS_MODULE"
	case CAP_SYS_RAWIO:
		return "CAP_SYS_RAWIO"
	case CAP_SYS_CHROOT:
		return "CAP_SYS_CHROOT"
	case CAP_SYS_PTRACE:
		return "CAP_SYS_PTRACE"
	case CAP_SYS_PACCT:
		return "CAP_SYS_PACCT"
	case CAP_SYS_ADMIN:
		return "CAP_SYS_ADMIN"
	case CAP_SYS_BOOT:
		return "CAP_SYS_BOOT"
	case CAP_SYS_NICE:
		return "CAP_SYS_NICE"
	case CAP_SYS_RESOURCE:
		return "CAP_SYS_RESOURCE"
	case CAP_SYS_TIME:
		return "CAP_SYS_TIME"
	case CAP_SYS_TTY_CONFIG:
		return "CAP_SYS_TTY_CONFIG"
	case CAP_MKNOD:
		return "CAP_MKNOD"
	case CAP_LEASE:
		return "CAP_LEASE"
	case CAP_AUDIT_WRITE:
		return "CAP_AUDIT_WRITE"
	case CAP_AUDIT_CONTROL:
		return "CAP_AUDIT_CONTROL"
	case CAP_SETFCAP:
		return "CAP_SETFCAP"
	case CAP_MAC_OVERRIDE:
		return "CAP_MAC_OVERRIDE"
	case CAP_MAC_ADMIN:
		return "CAP_MAC_ADMIN"
	case CAP_SYSLOG:
		return "CAP_SYSLOG"
	case CAP_WAKE_ALARM:
		return "CAP_WAKE_ALARM"
	case CAP_BLOCK_SUSPEND:
		return "CAP_BLOCK_SUSPEND"
	case CAP_AUDIT_READ:
		return "CAP_AUDIT_READ"
	default:
		return "UNKNOWN"
	}
}

func (cp Capability) TrimmedString() string {
	const capPrefix = "CAP_"
	s := cp.String()
	if !strings.HasPrefix(s, capPrefix) {
		return s
	}
	return s[len(capPrefix):]
}

func CapabilityFromString(capability string) (Capability, bool) {
	for cp := Capability(0); cp <= CAP_LAST_CAP; cp++ {
		if !cp.Ok() {
			continue
		}
		if cp.String() == capability {
			return cp, true
		}
	}
	return -1, false
}

func AllCapabilities() []Capability {
	allCapapabilities := make([]Capability, 0, CAP_LAST_CAP+1)
	for cp := Capability(0); cp <= CAP_LAST_CAP; cp++ {
		if !cp.Ok() {
			continue
		}
		allCapapabilities = append(allCapapabilities, cp)
	}
	return allCapapabilities
}

const (
	LINUX_CAPABILITY_VERSION_1 = 0x19980330

	LINUX_CAPABILITY_VERSION_2 = 0x20071026
	LINUX_CAPABILITY_VERSION_3 = 0x20080522

	HighestCapabilityVersion = LINUX_CAPABILITY_VERSION_3
)

const (
	VFS_CAP_FLAGS_EFFECTIVE = 0x000001
	VFS_CAP_REVISION_2 = 0x02000000
	VFS_CAP_REVISION_3    = 0x03000000
	VFS_CAP_REVISION_MASK = 0xFF000000
	XATTR_CAPS_SZ_2 = 20
	XATTR_CAPS_SZ_3 = 24
)

type VfsCapData struct {
	_             structs.HostLayout
	MagicEtc      uint32
	PermittedLo   uint32
	InheritableLo uint32
	PermittedHi   uint32
	InheritableHi uint32
}

func (c *VfsCapData) Permitted() uint64 {
	return uint64(c.PermittedHi)<<32 | uint64(c.PermittedLo)
}

func (c *VfsCapData) Inheritable() uint64 {
	return uint64(c.InheritableHi)<<32 | uint64(c.InheritableLo)
}

func (c *VfsCapData) IsRevision2() bool {
	return (c.MagicEtc & VFS_CAP_REVISION_MASK) == VFS_CAP_REVISION_2
}

func (c *VfsCapData) ToString() string {
	buf := make([]byte, c.SizeBytes())
	c.MarshalUnsafe(buf)
	return string(buf)
}

type VfsNsCapData struct {
	_ structs.HostLayout
	VfsCapData
	RootID uint32
}

func (c *VfsNsCapData) ConvertToV3(rootid uint32) {
	c.RootID = rootid
	if c.IsRevision2() {
		c.MagicEtc = VFS_CAP_REVISION_3 | c.MagicEtc&VFS_CAP_FLAGS_EFFECTIVE
	}
}

func (c *VfsNsCapData) ConvertToV2() {
	c.RootID = 0
	if !c.IsRevision2() {
		c.MagicEtc = VFS_CAP_REVISION_2 | c.MagicEtc&VFS_CAP_FLAGS_EFFECTIVE
	}
}

func (c *VfsNsCapData) ToString() string {
	if c.IsRevision2() {
		return c.VfsCapData.ToString()
	}
	buf := make([]byte, c.SizeBytes())
	c.MarshalUnsafe(buf)
	return string(buf)
}

type CapUserHeader struct {
	_       structs.HostLayout
	Version uint32
	Pid     int32
}

type CapUserData struct {
	_           structs.HostLayout
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}
