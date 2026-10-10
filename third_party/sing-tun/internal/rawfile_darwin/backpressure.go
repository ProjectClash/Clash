//go:build darwin

package rawfile

import (
	"time"

	"golang.org/x/sys/unix"
)

func BufferFull(errno unix.Errno) bool {
	return errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.ENOBUFS || errno == unix.ENOMEM
}

var bufferFullWaits = [...]time.Duration{
	50 * time.Microsecond,
	100 * time.Microsecond,
	200 * time.Microsecond,
	400 * time.Microsecond,
	800 * time.Microsecond,
	1600 * time.Microsecond,
	3200 * time.Microsecond,
	6400 * time.Microsecond,
}

const BufferFullWaitBudget = 12750 * time.Microsecond

func WaitBufferFull(attempt int) bool {
	if attempt < 0 || attempt >= len(bufferFullWaits) {
		return false
	}
	time.Sleep(bufferFullWaits[attempt])
	return true
}
