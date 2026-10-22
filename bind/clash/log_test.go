package clash

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type blockingPlatform struct {
	recordingPlatform
	release  chan struct{}
	received atomic.Int64
}

func (p *blockingPlatform) WriteLog(string) {
	p.received.Add(1)
	<-p.release
}

func TestLogBackpressureDoesNotBlockCore(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })

	done := make(chan struct{})
	go func() {
		for i := 0; i < logChannelSize*4; i++ {
			logrus.Infoln("clash backpressure probe")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("core logging blocked on a stalled WriteLog consumer")
	}

	writer.Close()
	close(platform.release)
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

func TestStartupLogsReachThePlatformBeforeWriteReturns(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := newRecordingPlatform()
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })

	logrus.Infoln("clash startup delivery probe")

	select {
	case line := <-platform.lines:
		if !strings.Contains(line, "clash startup delivery probe") {
			t.Fatalf("the platform received %q instead of the startup line", line)
		}
	default:
		t.Fatal("Write returned while the startup line was still queued in-process")
	}
}

func TestStartupDeliveryWaitIsSpentOnlyOnce(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })

	start := time.Now()
	for i := 0; i < 8; i++ {
		logrus.Infoln("clash stalled startup probe")
	}
	elapsed := time.Since(start)
	if elapsed < startupDeliveryBudget {
		t.Fatalf("the first startup line was not awaited: %v", elapsed)
	}
	if elapsed > 2*startupDeliveryBudget {
		t.Fatalf("a stalled platform was awaited more than once: %v", elapsed)
	}

	writer.Close()
	close(platform.release)
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

func TestEstablishedTunnelLoggingDoesNotWaitForThePlatform(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	start := time.Now()
	for i := 0; i < 8; i++ {
		logrus.Infoln("clash steady probe")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("steady-state Write waited %v on a stalled platform", elapsed)
	}

	writer.Close()
	close(platform.release)
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

func TestRedirectLogsStopsReplacedWriter(t *testing.T) {
	first := redirectLogs(newRecordingPlatform())
	second := redirectLogs(newRecordingPlatform())
	t.Cleanup(func() { stopLogRedirect(second) })
	select {
	case <-first.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("replaced log writer did not stop")
	}
}

func TestRecentLogRingHonorsConfiguredMaximum(t *testing.T) {
	ring := &ringBuffer{}
	ring.setMax(3)
	for _, line := range []string{"one", "two", "three", "four"} {
		ring.add(line)
	}
	got := ring.snapshot()
	if len(got) != 3 || got[0] != "two" || got[2] != "four" {
		t.Fatalf("bounded ring = %v", got)
	}
}

func TestSetupLinesGoToTheNextWriterOnce(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	logRedirectMu.Lock()
	attached := activeLogWriter
	logRedirectMu.Unlock()
	stopLogRedirect(attached)

	release := holdSetupLogs()
	logrus.Warnln("clash setup hold probe")
	release()

	first := newRecordingPlatform()
	writer := redirectLogs(first)
	select {
	case line := <-first.lines:
		if !strings.Contains(line, "clash setup hold probe") {
			t.Fatalf("the first writer was given %q before Setup's line", line)
		}
	default:
		t.Fatal("the line Setup wrote never reached the writer attached after it")
	}
	stopLogRedirect(writer)

	second := newRecordingPlatform()
	writer = redirectLogs(second)
	t.Cleanup(func() { stopLogRedirect(writer) })
	select {
	case line := <-second.lines:
		t.Fatalf("a later writer was given %q again", line)
	default:
	}
}
