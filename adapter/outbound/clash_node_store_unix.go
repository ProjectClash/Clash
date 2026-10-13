//go:build unix

package outbound

import (
	"os"
	"syscall"
)

func mapNodeRecords(file *os.File, size int) ([]byte, error) {
	return syscall.Mmap(int(file.Fd()), 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
}

func unmapNodeRecords(data []byte) { _ = syscall.Munmap(data) }

func nodeStoreProcessGone(pid int) bool {
	return syscall.Kill(pid, 0) == syscall.ESRCH
}
