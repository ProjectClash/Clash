package tun

import (
	"errors"
	"syscall"
	"time"
)

const (
	deviceFailurePersistence = 5 * time.Second
	deviceFailureEpisodeGap  = time.Second
	deviceFailureMaxBackoff  = 100 * time.Millisecond
)

var (
	deviceFailureNow   = time.Now
	deviceFailureSleep = time.Sleep
)

func fatalDeviceError(err error) bool {
	return errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENETDOWN)
}

func (t *NativeTun) readFailed(err error) bool {
	if t.closing.Load() {
		return true
	}
	if t.options.DeviceFailure == nil {
		return false
	}
	now := deviceFailureNow()
	t.failureMu.Lock()
	if t.failingSince.IsZero() || now.Sub(t.lastFailure) > deviceFailureEpisodeGap {
		t.failingSince, t.failureBackoff = now, time.Millisecond
	}
	t.lastFailure = now
	persistent := now.Sub(t.failingSince) >= deviceFailurePersistence
	backoff := t.failureBackoff
	if t.failureBackoff *= 2; t.failureBackoff > deviceFailureMaxBackoff {
		t.failureBackoff = deviceFailureMaxBackoff
	}
	t.failureMu.Unlock()
	if fatalDeviceError(err) || persistent {
		t.reportFailure(err)
		return true
	}
	deviceFailureSleep(backoff)
	return false
}
