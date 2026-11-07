//go:build darwin

package tun

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestAFailedUtunIsReportedOnceAndNotWhileClosing(t *testing.T) {
	reports := make(chan error, 4)
	device := &NativeTun{options: Options{DeviceFailure: func(err error) { reports <- err }}}
	device.reportFailure(syscall.EBADF)
	device.reportFailure(syscall.ENXIO)
	select {
	case err := <-reports:
		if !errors.Is(err, syscall.EBADF) {
			t.Fatalf("reported %v, want the first error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("a failed utun was not reported")
	}
	select {
	case err := <-reports:
		t.Fatalf("reported a second time: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	closing := &NativeTun{options: Options{DeviceFailure: func(err error) { reports <- err }}}
	closing.closing.Store(true)
	closing.reportFailure(syscall.EBADF)
	select {
	case err := <-reports:
		t.Fatalf("an error of the utun's own close was reported: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	(&NativeTun{}).reportFailure(syscall.EBADF)
}

type failingTun struct {
	err      error
	reads    int
	reported []error
}

func (d *failingTun) Read([]byte) (int, error)    { d.reads++; return 0, d.err }
func (d *failingTun) Write(p []byte) (int, error) { return len(p), nil }
func (d *failingTun) Close() error                { return nil }
func (d *failingTun) readFailed(err error) bool   { d.reported = append(d.reported, err); return true }

func TestTheUtunFailsClosedOnlyOnErrorsThatDoNotPass(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	var slept []time.Duration
	deviceFailureNow = func() time.Time { return now }
	deviceFailureSleep = func(d time.Duration) { slept = append(slept, d); now = now.Add(d) }
	t.Cleanup(func() { deviceFailureNow, deviceFailureSleep = time.Now, time.Sleep })

	reports := make(chan error, 8)
	owned := func() *NativeTun {
		return &NativeTun{options: Options{DeviceFailure: func(err error) { reports <- err }}}
	}
	told := func(want error) {
		t.Helper()
		select {
		case err := <-reports:
			if !errors.Is(err, want) {
				t.Fatalf("told %v, want %v", err, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("not told of %v", want)
		}
	}
	untold := func() {
		t.Helper()
		select {
		case err := <-reports:
			t.Fatalf("told %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}

	for _, gone := range []error{syscall.EBADF, syscall.ENXIO, syscall.ENODEV, syscall.ENETDOWN} {
		if !owned().readFailed(gone) {
			t.Fatalf("%v did not stop the reader", gone)
		}
		told(gone)
	}

	device := owned()
	for i := 0; i < 20; i++ {
		if device.readFailed(syscall.ENOBUFS) {
			t.Fatalf("an error that may pass stopped the reader after %v", now.Sub(time.Unix(1_000_000, 0)))
		}
	}
	untold()
	if len(slept) == 0 || slept[len(slept)-1] != deviceFailureMaxBackoff || slept[0] != time.Millisecond {
		t.Fatalf("backed off %v, want from 1ms doubling to %v", slept, deviceFailureMaxBackoff)
	}
	for !device.readFailed(syscall.ENOBUFS) {
		if now.Sub(time.Unix(1_000_000, 0)) > 2*deviceFailurePersistence {
			t.Fatal("errors that lasted past the persistence never stopped the reader")
		}
	}
	told(syscall.ENOBUFS)

	device = owned()
	device.readFailed(syscall.ENOMEM)
	now = now.Add(deviceFailurePersistence * 2)
	if device.readFailed(syscall.ENOMEM) {
		t.Fatal("a second error after a quiet gap counted the gap as persistence")
	}
	untold()

	if (&NativeTun{}).readFailed(syscall.EBADF) {
		t.Fatal("a device nobody listens for stopped its reader")
	}
	closing := owned()
	closing.closing.Store(true)
	if !closing.readFailed(syscall.EBADF) {
		t.Fatal("an error of the device's own close did not stop the reader")
	}
	untold()
}
