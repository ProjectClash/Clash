//go:build unix

package provider

import (
	"os"
	"syscall"
)

func mapClassicalIndex(file *os.File, size int) ([]byte, error) {
	return syscall.Mmap(int(file.Fd()), 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
}

func unmapClassicalIndex(data []byte) { _ = syscall.Munmap(data) }
