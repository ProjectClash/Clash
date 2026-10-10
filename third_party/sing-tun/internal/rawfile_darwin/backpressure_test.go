//go:build darwin

package rawfile

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestBufferFullNamesOnlyTheTransientErrnos(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EAGAIN, unix.EWOULDBLOCK, unix.ENOBUFS, unix.ENOMEM} {
		if !BufferFull(errno) {
			t.Errorf("BufferFull(%v) = false, want true", errno)
		}
	}
	for _, errno := range []unix.Errno{unix.EBADF, unix.EPIPE, unix.EINVAL, unix.ENXIO, unix.EMSGSIZE, unix.EINTR} {
		if BufferFull(errno) {
			t.Errorf("BufferFull(%v) = true, want false: this errno does not clear on its own", errno)
		}
	}
}

func TestWaitBufferFullIsBoundedAndMatchesItsStatedBudget(t *testing.T) {
	var total time.Duration
	for _, step := range bufferFullWaits {
		total += step
	}
	if total != BufferFullWaitBudget {
		t.Fatalf("schedule sums to %s, but BufferFullWaitBudget says %s", total, BufferFullWaitBudget)
	}
	started := time.Now()
	attempts := 0
	for WaitBufferFull(attempts) {
		attempts++
	}
	if attempts != len(bufferFullWaits) {
		t.Fatalf("schedule allowed %d waits, want %d", attempts, len(bufferFullWaits))
	}
	if elapsed := time.Since(started); elapsed < BufferFullWaitBudget || elapsed > 20*BufferFullWaitBudget {
		t.Fatalf("spent %s on the schedule, want between %s and %s", elapsed, BufferFullWaitBudget, 20*BufferFullWaitBudget)
	}
	if WaitBufferFull(-1) {
		t.Fatal("a negative attempt must not wait")
	}
}
