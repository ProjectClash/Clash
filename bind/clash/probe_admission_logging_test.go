package clash

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/log"
)

func captureProbeAdmissionLogs(t *testing.T, action func()) []log.Event {
	t.Helper()
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	const done = "probe-admission-logging-test-complete"
	result := make(chan []log.Event, 1)
	go func() {
		var events []log.Event
		for e := range sub {
			if e.Payload == done {
				result <- events
				return
			}
			if strings.HasPrefix(e.Payload, "[Memory] probe admission") {
				events = append(events, e)
			}
		}
	}()
	action()
	log.Infoln(done)
	select {
	case events := <-result:
		return events
	case <-time.After(5 * time.Second):
		t.Fatal("log stream did not drain")
		return nil
	}
}

func TestProbeAdmissionLogStormIsBounded(t *testing.T) {
	old := log.Level()
	log.SetLevel(log.INFO)
	defer log.SetLevel(old)
	hook := newProbeAdmissionHook(testAdmissionConfig(1, 1))
	ctx, cancel := context.WithCancel(adapter.WithBackgroundProbe(context.Background()))
	cancel()
	events := captureProbeAdmissionLogs(t, func() {
		for i := 0; i < 1000; i++ {
			if _, err := hook(ctx); err != adapter.ErrURLTestDeferred {
				t.Fatalf("probe %d changed its outcome: %v", i, err)
			}
		}
	})
	if len(events) != 1 {
		t.Errorf("1000 skipped probes emitted %d events, want one immediate summary", len(events))
	}
}

func TestProbeAdmissionLogWindowCountsAndIdleTail(t *testing.T) {
	var d probeAdmissionDiagnostics
	start := time.Unix(100, 0)
	first, emit := d.observe(start, 300*time.Millisecond, probeDeferred, true)
	if !emit || first.counts[1][probeDeferred] != 1 || first.elapsed != 0 {
		t.Fatalf("first event missing: %+v %v", first, emit)
	}
	if _, emit = d.observe(start.Add(time.Second), 3*time.Second, probeForced, false); emit {
		t.Fatal("forced event bypassed the window")
	}
	if _, emit = d.observe(start.Add(30*time.Second-time.Nanosecond), time.Second, probeAdmitted, true); emit {
		t.Fatal("window emitted early")
	}
	next, emit := d.observe(start.Add(30*time.Second), 200*time.Millisecond, probeDeferred, false)
	if !emit || next.elapsed != 30*time.Second || next.maxWait != 3*time.Second {
		t.Fatalf("boundary: %+v %v", next, emit)
	}
	var want [2][4]uint64
	want[0][probeForced] = 1
	want[1][probeAdmitted] = 1
	want[0][probeDeferred] = 1
	if next.counts != want {
		t.Fatalf("counts lost/duplicated: %v want %v", next.counts, want)
	}
	if _, emit = d.observe(start.Add(31*time.Second), time.Second, probeDeferred, true); emit {
		t.Fatal("tail emitted early")
	}
	tail, emit := d.observe(start.Add(time.Hour), time.Millisecond, probeAdmitted, false)
	if !emit || tail.counts[1][probeDeferred] != 1 || tail.counts[0][probeAdmitted] != 1 || tail.maxWait != time.Second {
		t.Fatalf("idle tail lost: %+v", tail)
	}
}

func TestProbeAdmissionLogConcurrentCounts(t *testing.T) {
	var d probeAdmissionDiagnostics
	start := time.Unix(100, 0)
	_, emit := d.observe(start, time.Millisecond, probeAdmitted, false)
	if !emit {
		t.Fatal("initial event missing")
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 64; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if _, emit := d.observe(start.Add(time.Second), time.Duration(i)*time.Millisecond, probeDeferred, worker%2 == 0); emit {
					t.Error("concurrent event escaped window")
				}
			}
		}(worker)
	}
	wg.Wait()
	got, emit := d.observe(start.Add(30*time.Second), 0, probeAdmitted, false)
	if !emit || got.counts[0][probeDeferred] != 32000 || got.counts[1][probeDeferred] != 32000 || got.counts[0][probeAdmitted] != 1 || got.maxWait != 999*time.Millisecond {
		t.Fatalf("concurrent accounting: %+v", got)
	}
}

func TestProbeAdmissionLogFastPathAndHookReset(t *testing.T) {
	old := log.Level()
	log.SetLevel(log.INFO)
	defer log.SetLevel(old)
	cfg := testAdmissionConfig(1000, 1000)
	hook := newProbeAdmissionHook(cfg)
	events := captureProbeAdmissionLogs(t, func() {
		for i := 0; i < 100; i++ {
			end, err := hook(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			end()
		}
	})
	if len(events) != 0 {
		t.Fatalf("probes admitted at once produced %d log events", len(events))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events = captureProbeAdmissionLogs(t, func() {
		if _, err := hook(ctx); err != adapter.ErrURLTestDeferred {
			t.Fatal(err)
		}
		if _, err := newProbeAdmissionHook(cfg)(ctx); err != adapter.ErrURLTestDeferred {
			t.Fatal(err)
		}
	})
	if len(events) != 2 {
		t.Fatalf("new hook inherited previous suppression: %d logs", len(events))
	}
}

func TestProbeAdmissionLogDebugKeepsDetails(t *testing.T) {
	old := log.Level()
	log.SetLevel(log.DEBUG)
	defer log.SetLevel(old)
	hook := newProbeAdmissionHook(testAdmissionConfig(1, 1))
	ctx, cancel := context.WithCancel(adapter.WithBackgroundProbe(context.Background()))
	cancel()
	events := captureProbeAdmissionLogs(t, func() {
		for i := 0; i < 32; i++ {
			if _, err := hook(ctx); err != adapter.ErrURLTestDeferred {
				t.Fatal(err)
			}
		}
	})
	var details, summaries int
	for _, event := range events {
		switch event.LogLevel {
		case log.DEBUG:
			details++
			for _, field := range []string{"waited ", "verdict=3", "background=true", "in_flight=0/0", "waiting=0/0"} {
				if !strings.Contains(event.Payload, field) {
					t.Errorf("detail missing %q: %s", field, event.Payload)
				}
			}
		case log.INFO:
			summaries++
			if !strings.Contains(event.Payload, "background_deferred=1") || !strings.Contains(event.Payload, "background_cap=1") {
				t.Errorf("summary missing count: %s", event.Payload)
			}
		default:
			t.Errorf("unexpected diagnostic level: %v", event.LogLevel)
		}
	}
	if details != 32 || summaries != 1 {
		t.Fatalf("debug: details=%d summaries=%d", details, summaries)
	}
}

func TestProbeAdmissionLogSuppressedPathDoesNotAllocate(t *testing.T) {
	var d probeAdmissionDiagnostics
	now := time.Unix(100, 0)
	d.observe(now, 0, probeDeferred, true)
	if n := testing.AllocsPerRun(1000, func() { d.observe(now, time.Millisecond, probeDeferred, true) }); n != 0 {
		t.Fatalf("suppressed diagnostic allocates %g objects", n)
	}
}
