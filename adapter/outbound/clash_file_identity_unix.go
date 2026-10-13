//go:build unix

package outbound

import (
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (dev, ino uint64) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), uint64(stat.Ino)
	}
	return 0, 0
}
