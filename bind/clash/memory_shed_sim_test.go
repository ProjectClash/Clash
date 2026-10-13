package clash

import (
	"fmt"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

type simWorld struct {
	start, now time.Time
	resident   uint64
	garbage    float64
	rate       float64
	flows      []*simFlow
	returning  []simReturn
	types      map[string]C.AdapterType
	every      func(w *simWorld)
	seq        int

	closed   []simClose
	resets   []time.Duration
	releases int
	peak     uint64
}

type simFlow struct {
	id          string
	node        string
	opened      time.Time
	holds       uint64
	stalled     bool
	sinceUpload time.Duration
	returnAfter time.Duration
}

type simReturn struct {
	at    time.Time
	bytes uint64
}

type simClose struct {
	at   time.Duration
	node string
}

func newSimWorld(resident uint64) *simWorld {
	start := time.Unix(1_000_000, 0)
	return &simWorld{start: start, now: start, resident: resident, types: map[string]C.AdapterType{"Trojan": C.Trojan, "HY2": C.Hysteria2}}
}

func (w *simWorld) open(node string, holds uint64) *simFlow {
	w.seq++
	flow := &simFlow{id: fmt.Sprintf("%s-%04d", node, w.seq), node: node, opened: w.now, holds: holds, sinceUpload: 10 * time.Millisecond}
	w.flows = append(w.flows, flow)
	return flow
}

func (w *simWorld) openMany(n int, node string, holds uint64) {
	for i := 0; i < n; i++ {
		w.open(node, holds)
	}
}

func (w *simWorld) age(d time.Duration) {
	w.now = w.now.Add(d)
	w.start = w.now
}

func (w *simWorld) wedge(n int, node string, returnAfter time.Duration) []*simFlow {
	var out []*simFlow
	for i := 0; i < n; i++ {
		flow := w.open(node, 0)
		flow.stalled, flow.sinceUpload, flow.returnAfter = true, time.Minute, returnAfter
		out = append(out, flow)
	}
	return out
}

func (w *simWorld) usage() uint64 {
	usage := w.resident + uint64(w.garbage)
	for _, flow := range w.flows {
		usage += flow.holds
	}
	for _, back := range w.returning {
		usage += back.bytes
	}
	return usage
}

func (w *simWorld) advance(d time.Duration) {
	w.garbage += w.rate * d.Seconds()
	w.now = w.now.Add(d)
	kept := w.returning[:0]
	for _, back := range w.returning {
		if back.at.After(w.now) {
			kept = append(kept, back)
		} else {
			w.garbage += float64(back.bytes)
		}
	}
	w.returning = kept
	w.peak = max(w.peak, w.usage())
}

func (w *simWorld) sample() pressureSample {
	s := atUsage(w.usage())
	s.connections = len(w.flows)
	return s
}

func (w *simWorld) views() []shedView {
	views := make([]shedView, 0, len(w.flows))
	for _, flow := range w.flows {
		view := shedView{id: flow.id, network: C.TCP, node: flow.node, age: w.now.Sub(flow.opened),
			sinceDownload: 10 * time.Millisecond, sinceUpload: flow.sinceUpload, queuedKnown: true}
		if flow.stalled {
			view.sinceDownload, view.queued = 5*time.Second, 128<<10
		}
		views = append(views, view)
	}
	return views
}

func (w *simWorld) deps() shedEpisodeDeps {
	return shedEpisodeDeps{
		sample: w.sample,
		candidates: func() []shedCandidate {
			return rankShedCandidates(w.views(), func(name string) (C.AdapterType, bool) {
				adapterType, ok := w.types[name]
				return adapterType, ok
			})
		},
		closeOne: func(candidate shedCandidate) {
			for i, flow := range w.flows {
				if flow.id != candidate.id {
					continue
				}
				w.flows = append(w.flows[:i], w.flows[i+1:]...)
				w.closed = append(w.closed, simClose{at: w.now.Sub(w.start), node: flow.node})
				if flow.returnAfter > 0 {
					w.returning = append(w.returning, simReturn{at: w.now.Add(flow.returnAfter), bytes: flow.holds})
				} else {
					w.garbage += float64(flow.holds)
				}
				return
			}
		},
		resetNode: func(string) { w.resets = append(w.resets, w.now.Sub(w.start)) },
		free:      w.release,
		settle: func(d time.Duration) bool {
			w.advance(d)
			return true
		},
	}
}

func (w *simWorld) release() { w.garbage = 0; w.releases++ }

func (w *simWorld) run(d time.Duration) {
	lines := limitLines()
	var ladder shedLadder
	for w.now.Sub(w.start) < d {
		if w.every != nil {
			w.every(w)
		}
		w.peak = max(w.peak, w.usage())
		step := ladder.step(lines, w.sample(), false, w.now)
		if step.freeMemory && !step.shed {
			w.release()
		}
		if step.shed {
			result := runShedEpisode(lines, w.deps(), step.mayClose)
			ladder.episodeDone(result, w.now)
		}
		w.advance(100 * time.Millisecond)
	}
}

func (w *simWorld) closedOn(node string, from, to time.Duration) int {
	n := 0
	for _, c := range w.closed {
		if (node == "" || c.node == node) && c.at >= from && c.at < to {
			n++
		}
	}
	return n
}

func (w *simWorld) batches() []time.Duration {
	var out []time.Duration
	for i, c := range w.closed {
		if i == 0 || c.at-w.closed[i-1].at > time.Second {
			out = append(out, c.at)
		}
	}
	return out
}

const simHardLine = 49 << 20

func TestGarbageThatAReleaseReturnsClosesNothing(t *testing.T) {
	w := newSimWorld(44*shedMiB + 512<<10)
	w.rate = float64(shedMiB)
	w.openMany(100, "Trojan", 0)
	w.age(time.Minute)
	w.run(time.Minute)
	t.Logf("a minute: %d closed, %d releases, peak %.2f MiB", len(w.closed), w.releases, mib(w.peak))
	if n := len(w.closed); n != 0 {
		t.Fatalf("closed %d connection(s) in a minute of garbage a release returns (first at %v)", n, w.closed[0].at)
	}
	if w.releases == 0 {
		t.Fatal("the garbage was never released")
	}
}

func TestClosesThatDoNotPayBackOff(t *testing.T) {
	w := newSimWorld(46 * shedMiB)
	w.openMany(100, "Trojan", 0)
	w.age(time.Minute)
	w.run(10 * time.Minute)
	batches := w.batches()
	t.Logf("first minute: %d closed; ten minutes: %d closed in %d batches at %v", w.closedOn("", 0, time.Minute), len(w.closed), len(batches), batches)
	if n := w.closedOn("", 0, time.Minute); n > 4*shedBatch {
		t.Fatalf("closed %d in the first minute of closes that never paid, want at most %d", n, 4*shedBatch)
	}
	if len(batches) < 3 {
		t.Fatalf("batches at %v: closing stopped altogether", batches)
	}
	if gap := batches[2] - batches[1]; gap < 10*time.Second {
		t.Fatalf("batches at %v: after two that did not pay, the third came %v later", batches, gap)
	}
	for i := 1; i < len(batches); i++ {
		if gap := batches[i] - batches[i-1]; gap > 2*time.Minute {
			t.Fatalf("batches at %v: a wait of %v; the close backoff is a minute at most", batches, gap)
		}
	}
}

func TestClosesThatPayStillTakeTheFootprintUnderTheLine(t *testing.T) {
	w := newSimWorld(48*shedMiB - 100*300<<10)
	w.openMany(100, "Trojan", 300<<10)
	w.age(time.Minute)
	w.run(30 * time.Second)
	t.Logf("30 s: %d closed, footprint %.2f MiB", len(w.closed), mib(w.usage()))
	if w.sample().usage >= limitLines().shed {
		t.Fatalf("footprint %.2f MiB after 30 s with %d closed; the closes pay and should have got it under 45", mib(w.usage()), len(w.closed))
	}
	if last := w.closed[len(w.closed)-1].at; last > 10*time.Second {
		t.Fatalf("the last close came at %v; paying closes must not wait out a backoff", last)
	}
	if n := len(w.closed); n > 16 {
		t.Fatalf("closed %d; 3 MiB at 300 KiB is about 11", n)
	}
}

func TestClosesKeepUpWithConnectionsThatKeepComing(t *testing.T) {
	w := newSimWorld(46*shedMiB - 100*uint64(shedTCPBaseBytes))
	w.openMany(100, "Trojan", uint64(shedTCPBaseBytes))
	w.age(time.Minute)
	next := w.now
	w.every = func(w *simWorld) {
		for !w.now.Before(next) {
			w.open("Trojan", uint64(shedTCPBaseBytes))
			next = next.Add(250 * time.Millisecond)
		}
	}
	w.run(2 * time.Minute)
	t.Logf("2 min: %d opened, %d closed, peak %.2f MiB, now %.2f MiB", w.seq, len(w.closed), mib(w.peak), mib(w.usage()))
	if w.peak >= simHardLine {
		t.Fatalf("peak %.2f MiB, at or over 49 (%d closed)", mib(w.peak), len(w.closed))
	}
	for from := 10 * time.Second; from < 2*time.Minute; from += 10 * time.Second {
		if w.closedOn("", from, from+10*time.Second) == 0 {
			t.Fatalf("nothing closed in [%v, %v) while four connections a second kept opening", from, from+10*time.Second)
		}
	}
}

func TestSlowSteadyGrowthNeverReachesTheHardLine(t *testing.T) {
	w := newSimWorld(30 * shedMiB)
	next := w.now
	w.every = func(w *simWorld) {
		for !w.now.Before(next) {
			w.open("Trojan", 60<<10)
			next = next.Add(500 * time.Millisecond)
		}
	}
	w.run(5 * time.Minute)
	t.Logf("5 min: %d opened, %d closed, peak %.2f MiB", w.seq, len(w.closed), mib(w.peak))
	if w.peak >= simHardLine {
		t.Fatalf("peak %.2f MiB, at or over 49 (%d closed)", mib(w.peak), len(w.closed))
	}
}

func TestAWedgedNodeIsShedWholeEachTimeAndNothingElse(t *testing.T) {
	w := newSimWorld(24 * shedMiB)
	w.openMany(40, "Trojan", uint64(shedTCPBaseBytes))
	w.age(time.Minute)
	var wedged []*simFlow
	var wedgedAt []time.Duration
	nextWedge := w.now.Add(5 * time.Second)
	w.every = func(w *simWorld) {
		if len(wedgedAt) < 2 && !w.now.Before(nextWedge) {
			wedgedAt = append(wedgedAt, w.now.Sub(w.start))
			wedged = w.wedge(20, "HY2", 2500*time.Millisecond)
			nextWedge = w.now.Add(time.Hour)
		}
		open := 0
		for _, flow := range wedged {
			if flow.holds < 1<<20 {
				flow.holds += 10 << 10
			}
			for _, live := range w.flows {
				if live == flow {
					open++
				}
			}
		}
		if wedged != nil && open == 0 {
			wedged = nil
			nextWedge = w.now.Add(20 * time.Second)
		}
	}
	w.run(90 * time.Second)
	t.Logf("90 s: wedged at %v, reset at %v, closed %d on HY2 and %d ordinary, peak %.2f MiB",
		wedgedAt, w.resets, w.closedOn("HY2", 0, time.Hour), w.closedOn("Trojan", 0, time.Hour), mib(w.peak))
	if n := w.closedOn("Trojan", 0, time.Hour); n != 0 {
		t.Fatalf("closed %d ordinary flow(s); the wedged node was the memory", n)
	}
	if len(wedgedAt) != 2 || len(w.resets) != 2 || w.closedOn("HY2", 0, time.Hour) != 40 {
		t.Fatalf("wedged at %v, node reset at %v, %d HY2 flows closed; want both wedges shed whole (40)", wedgedAt, w.resets, w.closedOn("HY2", 0, time.Hour))
	}
	for i := range wedgedAt {
		if late := w.resets[i] - wedgedAt[i]; late > 11*time.Second {
			t.Fatalf("wedge %d at %v was reset %v later; it was over the line well before", i+1, wedgedAt[i], late)
		}
	}
	if w.peak >= simHardLine {
		t.Fatalf("peak %.2f MiB, at or over 49", mib(w.peak))
	}
}

func TestAStalledFlowStillSendingKeepsItsNodeUp(t *testing.T) {
	w := newSimWorld(26 * shedMiB)
	w.openMany(40, "Trojan", uint64(shedTCPBaseBytes))
	for i, flow := range w.wedge(20, "HY2", 2500*time.Millisecond) {
		flow.holds = 1 << 20
		if i == 0 {
			flow.sinceUpload = time.Millisecond
		}
	}
	w.age(time.Minute)
	w.run(30 * time.Second)
	t.Logf("30 s: resets at %v, closed %d on HY2, %d ordinary", w.resets, w.closedOn("HY2", 0, time.Hour), w.closedOn("Trojan", 0, time.Hour))
	if len(w.resets) != 0 || w.closedOn("HY2", 0, time.Hour) != 0 {
		t.Fatalf("node reset at %v with %d HY2 flows closed, while one of its flows was still sending", w.resets, w.closedOn("HY2", 0, time.Hour))
	}
}
