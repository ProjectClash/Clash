// Copyright 2019 The gVisor Authors.


//go:build arm64
// +build arm64

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"
)

const (
	O_DIRECTORY = 000040000
	O_NOFOLLOW  = 000100000
	O_DIRECT    = 000200000
	O_LARGEFILE = 000400000
)

type Stat struct {
	_       structs.HostLayout
	Dev     uint64
	Ino     uint64
	Mode    uint32
	Nlink   uint32
	UID     uint32
	GID     uint32
	Rdev    uint64
	_       uint64
	Size    int64
	Blksize int32
	_       int32
	Blocks  int64
	ATime   Timespec
	MTime   Timespec
	CTime   Timespec
	_       [2]int32
}
