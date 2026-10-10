//go:build unix

package adapter

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func errnoName(errno syscall.Errno) string {
	return unix.ErrnoName(errno)
}
