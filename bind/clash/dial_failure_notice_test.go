package clash

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/log"
)

type warningCapture struct {
	mu       sync.Mutex
	payloads []string
}

func captureWarnings(t *testing.T) *warningCapture {
	t.Helper()
	capture := &warningCapture{}
	subscription := log.Subscribe()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case event, open := <-subscription:
				if !open {
					return
				}
				capture.mu.Lock()
				capture.payloads = append(capture.payloads, event.Payload)
				capture.mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		log.UnSubscribe(subscription)
		close(stop)
		<-done
	})
	return capture
}

func (c *warningCapture) matching(fragment string) []string {
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	var found []string
	for _, payload := range c.payloads {
		if strings.Contains(payload, fragment) {
			found = append(found, payload)
		}
	}
	return found
}

func resetDialFailureWatch(t *testing.T) {
	t.Helper()
	dialFailureWatch.Lock()
	dialFailureWatch.consecutive = 0
	dialFailureWatch.firstError = ""
	dialFailureWatch.firstErr = nil
	dialFailureWatch.firstAt = time.Time{}
	dialFailureWatch.announced = false
	dialFailureWatch.Unlock()
	t.Cleanup(func() {
		dialFailureWatch.Lock()
		dialFailureWatch.consecutive = 0
		dialFailureWatch.firstError = ""
		dialFailureWatch.firstErr = nil
		dialFailureWatch.firstAt = time.Time{}
		dialFailureWatch.announced = false
		dialFailureWatch.Unlock()
	})
}

func permissionDenied(_ string) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("93.184.216.34"), Port: 443},
		Err:  &os.SyscallError{Syscall: "connect", Err: syscall.EPERM},
	}
}

func TestARunOfIdenticalRefusalsSaysSomethingOnce(t *testing.T) {
	resetDialFailureWatch(t)
	logs := captureWarnings(t)

	for i := 0; i < consecutiveDialFailuresBeforeNotice*3; i++ {
		observeDialOutcomeForNotice(permissionDenied(fmt.Sprintf("10.0.0.%d:443", i%200)))
	}

	notices := logs.matching("[Apple]")
	if len(notices) != 1 {
		t.Fatalf("expected exactly one notice for a run of %d identical failures, got %d:\n%s",
			consecutiveDialFailuresBeforeNotice*3, len(notices), strings.Join(notices, "\n"))
	}
	for _, required := range []string{"in a row", "entitlement"} {
		if !strings.Contains(notices[0], required) {
			t.Errorf("the notice never mentions %q, so a reader cannot act on it:\n%s", required, notices[0])
		}
	}
}

func TestOneSuccessResetsTheRun(t *testing.T) {
	resetDialFailureWatch(t)
	logs := captureWarnings(t)

	for i := 0; i < consecutiveDialFailuresBeforeNotice-1; i++ {
		observeDialOutcomeForNotice(permissionDenied("10.0.0.1:443"))
	}
	observeDialOutcomeForNotice(nil)
	for i := 0; i < consecutiveDialFailuresBeforeNotice-1; i++ {
		observeDialOutcomeForNotice(permissionDenied("10.0.0.2:443"))
	}

	if notices := logs.matching("[Apple]"); len(notices) != 0 {
		t.Errorf("a success in the middle should have reset the run, but got:\n%s", strings.Join(notices, "\n"))
	}
}

func TestMixedFailuresDoNotAccumulateIntoOneCause(t *testing.T) {
	resetDialFailureWatch(t)
	logs := captureWarnings(t)

	for i := 0; i < consecutiveDialFailuresBeforeNotice*2; i++ {
		if i%2 == 0 {
			observeDialOutcomeForNotice(permissionDenied("10.0.0.1:443"))
		} else {
			observeDialOutcomeForNotice(errors.New("dial tcp 10.0.0.2:443: i/o timeout"))
		}
	}

	if notices := logs.matching("[Apple]"); len(notices) != 0 {
		t.Errorf("alternating causes should not produce a notice blaming one of them:\n%s",
			strings.Join(notices, "\n"))
	}
}

func TestFailuresAboutDifferentAddressesStillCountAsTheSameComplaint(t *testing.T) {
	first := "dial tcp 93.184.216.34:443: connect: operation not permitted"
	second := "dial tcp 1.1.1.1:853: connect: operation not permitted"
	if !sameDialFailure(first, second) {
		t.Error("two refusals of different destinations were treated as different complaints, so " +
			"a run of them would never reach the threshold")
	}
	if sameDialFailure(first, "dial tcp 1.1.1.1:853: i/o timeout") {
		t.Error("a timeout and a refusal were treated as the same complaint")
	}
}
