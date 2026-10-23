//go:build darwin || linux

package clashsum

import (
	"os"
	"syscall"
)

func stampOf(info os.FileInfo) (Stamp, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Stamp{}, false
	}
	return Stamp{
		dev:      uint64(stat.Dev),
		ino:      uint64(stat.Ino),
		size:     info.Size(),
		modified: info.ModTime().UnixNano(),
		changed:  changeTime(stat),
	}, true
}

func openFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
