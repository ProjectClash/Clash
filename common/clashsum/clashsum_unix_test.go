//go:build darwin || linux

package clashsum

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAFIFOIsRefusedWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Check(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Check waited on a FIFO")
	}
}
