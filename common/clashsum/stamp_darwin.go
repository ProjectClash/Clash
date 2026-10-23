package clashsum

import (
	"syscall"
	"time"
)

func changeTime(stat *syscall.Stat_t) int64 {
	return stat.Ctimespec.Sec*1e9 + stat.Ctimespec.Nsec
}

const platformRacyMargin = time.Millisecond
