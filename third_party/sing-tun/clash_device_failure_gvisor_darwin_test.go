//go:build darwin && with_gvisor

package tun

import (
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

func TestTheGVisorEndpointEndingWithAnErrorIsAFailedUtun(t *testing.T) {
	reports := make(chan error, 2)
	device := &NativeTun{options: Options{DeviceFailure: func(err error) { reports <- err }}}
	device.endpointClosed(nil)
	select {
	case err := <-reports:
		t.Fatalf("a stopped device was reported as failed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	device.endpointClosed(&tcpip.ErrBadLocalAddress{})
	select {
	case err := <-reports:
		if err == nil || err.Error() == "" {
			t.Fatalf("reported %v, want the endpoint's error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("a dispatch loop that ended with an error was not reported")
	}
}
