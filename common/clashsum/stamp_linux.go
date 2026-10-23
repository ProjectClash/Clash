package clashsum

import (
	"syscall"
	"time"
)

func changeTime(stat *syscall.Stat_t) int64 {
	return int64(stat.Ctim.Sec)*1e9 + int64(stat.Ctim.Nsec)
}

const platformRacyMargin = 100 * time.Millisecond
