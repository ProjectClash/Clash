//go:build !unix

package adapter

import "syscall"

func errnoName(syscall.Errno) string { return "" }
