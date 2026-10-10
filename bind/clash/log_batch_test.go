package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type batchRecorder struct {
	mu      sync.Mutex
	raw     []string
	batches [][]string
	gate    chan struct{}
	gated   bool
}

func (r *batchRecorder) WriteLogBatch(linesJSON string) {
	var lines []string
	if err := json.Unmarshal([]byte(linesJSON), &lines); err != nil {
		panic(fmt.Sprintf("a batch is a JSON array of strings: %v in %q", err, linesJSON))
	}
	r.mu.Lock()
	r.raw = append(r.raw, linesJSON)
	r.batches = append(r.batches, lines)
	first := !r.gated
	r.gated = true
	r.mu.Unlock()
	if first && r.gate != nil {
		<-r.gate
	}
}

func (r *batchRecorder) lines() (all []string, calls int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, batch := range r.batches {
		all = append(all, batch...)
	}
	return all, len(r.batches)
}

func useBatchWriter(t *testing.T, writer LogBatchWriter) {
	t.Helper()
	SetLogBatchWriter(writer)
	t.Cleanup(func() { SetLogBatchWriter(nil) })
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
}

func TestQueuedLogLinesCrossTheBridgeTogether(t *testing.T) {
	recorder := &batchRecorder{gate: make(chan struct{})}
	useBatchWriter(t, recorder)
	platform := newRecordingPlatform()
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	const count = 300
	var want []string
	for i := 0; i < count; i++ {
		line := fmt.Sprintf("clash batch probe %03d", i)
		want = append(want, line)
		logrus.Infoln(line)
	}
	close(recorder.gate)
	if !logBatchWait(func() bool { got, _ := recorder.lines(); return len(got) >= count }, 5*time.Second) {
		got, _ := recorder.lines()
		t.Fatalf("only %d of %d lines crossed", len(got), count)
	}
	got, calls := recorder.lines()
	if len(got) != count {
		t.Fatalf("%d lines crossed, want exactly %d", len(got), count)
	}
	for i, line := range got {
		if !strings.Contains(line, want[i]) {
			t.Fatalf("line %d is %q, want the line written %d-th (%q): order or content changed", i, line, i, want[i])
		}
	}
	if calls >= count/2 {
		t.Fatalf("%d lines took %d bridge calls: the queue was not batched", count, calls)
	}
	select {
	case line := <-platform.lines:
		t.Fatalf("a line also went through WriteLog once batches were taken: %q", line)
	default:
	}
}

func TestALoneLogLineDoesNotWaitForCompany(t *testing.T) {
	recorder := &batchRecorder{}
	useBatchWriter(t, recorder)
	writer := redirectLogs(newRecordingPlatform())
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	logrus.Infoln("clash lone line")
	if !logBatchWait(func() bool { got, _ := recorder.lines(); return len(got) == 1 }, 100*time.Millisecond) {
		t.Fatal("a lone line did not cross within 100 ms")
	}
}

func TestStartupLinesInABatchAreDeliveredBeforeWriteReturns(t *testing.T) {
	recorder := &batchRecorder{}
	useBatchWriter(t, recorder)
	writer := redirectLogs(newRecordingPlatform())
	t.Cleanup(func() { stopLogRedirect(writer) })

	began := time.Now()
	logrus.Infoln("clash startup batch probe")
	if took := time.Since(began); took >= startupDeliveryBudget/2 || writer.platformStalled.Load() {
		t.Fatalf("Write waited %s and the writer thinks the platform stalled (%v): the batch was not acknowledged", took, writer.platformStalled.Load())
	}
	got, _ := recorder.lines()
	if len(got) != 1 || !strings.Contains(got[0], "clash startup batch probe") {
		t.Fatalf("Write returned before the startup line was handed over: %q", got)
	}
}

func TestABatchCarriesInvalidUTF8RepairedAsASingleLineWould(t *testing.T) {
	recorder := &batchRecorder{}
	useBatchWriter(t, recorder)
	writer := redirectLogs(newRecordingPlatform())
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	_, _ = writer.Write([]byte("clash bad byte \xff\xfe here\n"))
	if !logBatchWait(func() bool { got, _ := recorder.lines(); return len(got) == 1 }, time.Second) {
		t.Fatal("the line never crossed")
	}
	got, _ := recorder.lines()
	if got[0] != bridgeSafeString("clash bad byte \xff\xfe here") {
		t.Fatalf("the line crossed as %q, not repaired as bridgeSafeString would", got[0])
	}
}

func logBatchWait(condition func() bool, within time.Duration) bool {
	until := time.Now().Add(within)
	for time.Now().Before(until) {
		if condition() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return condition()
}

func TestABatchIsBoundedBySizeAndKeepsMarkupAsIs(t *testing.T) {
	recorder := &batchRecorder{gate: make(chan struct{})}
	useBatchWriter(t, recorder)
	writer := redirectLogs(newRecordingPlatform())
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	long := strings.Repeat("<a&b>", 20<<10)
	_, _ = writer.Write([]byte("first\n"))
	for i := 0; i < 6; i++ {
		_, _ = writer.Write([]byte(long + "\n"))
	}
	close(recorder.gate)
	if !logBatchWait(func() bool { got, _ := recorder.lines(); return len(got) == 7 }, 5*time.Second) {
		got, _ := recorder.lines()
		t.Fatalf("%d of 7 lines crossed", len(got))
	}
	got, calls := recorder.lines()
	for _, line := range got[1:] {
		if line != long {
			t.Fatalf("a long line crossed changed: %d bytes, want %d", len(line), len(long))
		}
	}
	if calls < 2 {
		t.Fatalf("600 KiB of backlog crossed in %d calls: the size bound did not split it", calls)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for _, raw := range recorder.raw[1:] {
		if !strings.Contains(raw, "<a&b>") || strings.HasSuffix(raw, "\n") {
			t.Fatalf("a batch escaped markup or kept the encoder's newline: %q...", raw[:min(len(raw), 80)])
		}
	}
	for _, batch := range recorder.batches {
		size := 0
		for _, line := range batch {
			size += len(line)
		}
		if size > logBatchBytes+len(long) {
			t.Fatalf("a batch carried %d bytes, past the bound by more than a line", size)
		}
	}
}
