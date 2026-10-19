package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func longLogLine(i int) string {
	head := fmt.Sprintf("[TCP] 198.18.0.1:%d --> app.example.com:443 match AND(", 10000+i)
	return head + strings.Repeat("x", 50<<10-len(head))
}

func TestRecentLogRingIsBoundedInBytesAndKeepsTheNewestLine(t *testing.T) {
	ring := &ringBuffer{}
	ring.setMax(1000)
	for i := 0; i < 1000; i++ {
		ring.add(longLogLine(i))
	}
	got := ring.snapshot()
	held := 0
	for _, line := range got {
		held += len(line)
	}
	if held > recentLogMaxBytes+len(longLogLine(0)) {
		t.Fatalf("1000 lines of 50 KB leave %d bytes in the ring, want at most %d plus one line", held, recentLogMaxBytes)
	}
	if len(got) == 0 || got[len(got)-1] != longLogLine(999) {
		t.Fatal("the newest line is not the ring's last")
	}
	for i, line := range got {
		if want := longLogLine(1000 - len(got) + i); line != want {
			t.Fatalf("line %d of the tail is not the line written in that place", i)
		}
	}

	huge := strings.Repeat("y", recentLogMaxBytes+1)
	ring.add(huge)
	if got := ring.snapshot(); len(got) != 1 || got[0] != huge {
		t.Fatalf("a line over the cap alone left %d lines, want it alone and whole", len(got))
	}
	ring.add("next")
	if got := ring.snapshot(); len(got) != 1 || got[0] != "next" {
		t.Fatalf("after a newer line the ring holds %d lines, want the newer one alone", len(got))
	}

	ring.setMax(1)
	ring.add("one")
	ring.add("two")
	if got := ring.snapshot(); len(got) != 1 || got[0] != "two" {
		t.Fatalf("setMax(1) ring = %v", got)
	}
}

func TestRecentLogRingLetsDroppedLinesGo(t *testing.T) {
	heap := func() int64 {
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return int64(stats.HeapAlloc)
	}
	ring := &ringBuffer{}
	ring.setMax(1000)
	before := heap()
	for i := 0; i < 1000; i++ {
		ring.add(fmt.Sprintf("[TCP] 198.18.0.1:%d --> www.example.org:443 match Match using DIRECT", 10000+i))
	}
	for i := 0; i < 200; i++ {
		ring.add(longLogLine(i))
	}
	held := heap() - before
	if limit := int64(recentLogMaxBytes + 4<<20); held > limit {
		t.Fatalf("after 1000 short lines and 200 of 50 KB the ring keeps %.1f MiB on the heap, want at most %.1f", float64(held)/(1<<20), float64(limit)/(1<<20))
	}
	runtime.KeepAlive(ring)
}

func TestRecentLogsJSONReturnsTheNewestLinesWithinTheCap(t *testing.T) {
	recentLogs.setMax(1000)
	t.Cleanup(func() {
		recentLogs.setMax(1)
		recentLogs.add("reset")
		recentLogs.setMax(defaultLogMaxLines)
	})
	for i := 0; i < 1000; i++ {
		recentLogs.add(longLogLine(i))
	}
	var lines []string
	if err := json.Unmarshal([]byte(RecentLogsJSON()), &lines); err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, line := range lines {
		held += len(line)
	}
	if held > recentLogMaxBytes+len(longLogLine(0)) {
		t.Fatalf("RecentLogsJSON returned %d bytes of lines, want at most %d plus one line", held, recentLogMaxBytes)
	}
	if len(lines) == 0 || lines[len(lines)-1] != longLogLine(999) {
		t.Fatal("RecentLogsJSON does not end with the newest line")
	}
}

func TestStalledPlatformQueueIsBoundedInBytes(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	t.Cleanup(func() {
		recentLogs.setMax(1)
		recentLogs.add("reset")
		recentLogs.setMax(defaultLogMaxLines)
	})

	platform := &blockingPlatform{release: make(chan struct{})}
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	line := longLogLine(0)
	for i := 0; i < logChannelSize; i++ {
		logrus.Infoln(line)
	}
	if queued := writer.queuedBytes.Load(); queued > logQueueMaxBytes+int64(len(line))+1024 {
		t.Fatalf("a stalled platform has %d bytes queued, want at most %d plus one line", queued, logQueueMaxBytes)
	}
	if writer.dropped.Load() == 0 {
		t.Fatal("no line was dropped behind a stalled platform past the byte bound")
	}

	writer.Close()
	close(platform.release)
	select {
	case <-writer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("log drain goroutine did not terminate")
	}
}

func TestPlatformQueueGivesItsBytesBackAsLinesLeave(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	t.Cleanup(func() {
		recentLogs.setMax(1)
		recentLogs.add("reset")
		recentLogs.setMax(defaultLogMaxLines)
	})

	platform := newRecordingPlatform()
	writer := redirectLogs(platform)
	t.Cleanup(func() { stopLogRedirect(writer) })
	writer.markTunnelEstablished()

	lines := 2*logQueueMaxBytes/len(longLogLine(0)) + 1
	for i := 0; i < lines; i++ {
		line := longLogLine(i)
		logrus.Infoln(line)
		deadline := time.After(2 * time.Second)
	wait:
		for {
			select {
			case got := <-platform.lines:
				if strings.Contains(got, line[:40]) {
					break wait
				}
			case <-deadline:
				t.Fatalf("line %d of %d never reached a healthy platform (%d dropped)", i, lines, writer.dropped.Load())
			}
		}
	}
	if dropped := writer.dropped.Load(); dropped != 0 {
		t.Fatalf("a healthy platform lost %d lines", dropped)
	}
}
