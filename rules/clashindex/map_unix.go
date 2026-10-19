//go:build unix

package clashindex

import (
	"os"
	"syscall"
)

func mapIndex(file *os.File, size int) ([]byte, error) {
	return syscall.Mmap(int(file.Fd()), 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
}

func unmapIndex(data []byte) { _ = syscall.Munmap(data) }

func openIndexFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
