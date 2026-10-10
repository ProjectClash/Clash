// Copyright 2020 The gVisor Authors.


//go:build amd64
// +build amd64

package linux

const (
	VSyscallStartAddr uint64 = 0xffffffffff600000
	VSyscallEndAddr   uint64 = 0xffffffffff601000
)
