// Copyright 2018 The gVisor Authors.


//go:build amd64
// +build amd64

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"
)

const (
	O_DIRECT    = 000040000
	O_LARGEFILE = 000100000
	O_DIRECTORY = 000200000
	O_NOFOLLOW  = 000400000
)

type Stat struct {
	_       structs.HostLayout
	Dev     uint64
	Ino     uint64
	Nlink   uint64
	Mode    uint32
	UID     uint32
	GID     uint32
	_       int32
	Rdev    uint64
	Size    int64
	Blksize int64
	Blocks  int64
	ATime   Timespec
	MTime   Timespec
	CTime   Timespec
	_       [3]int64
}
