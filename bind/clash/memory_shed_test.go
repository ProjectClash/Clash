package clash

import (
	"fmt"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

const shedMiB = uint64(1 << 20)

func limitLines() shedLines {
	return computeShedLines(thresholdModeLimit, testLimit)
}

func TestNoLayersWithoutABudget(t *testing.T) {
	for _, mode := range []thresholdMode{thresholdModeAvailable, thresholdModeNone} {
		lines := computeShedLines(mode, 0)
		var ladder shedLadder
		sample := pressureSample{usage: 49 * shedMiB, available: 1, availableKnown: true}
		if out := ladder.step(lines, sample, true, time.Unix(0, 0)); out.release || out.pace || out.shed || out.freeMemory {
			t.Fatalf("%v mode acted: %+v", mode, out)
		}
	}
}

func TestShedLinesOnTheIOSBudget(t *testing.T) {
	lines := limitLines()
	for _, check := range []struct {
		name      string
		got, want uint64
	}{
		{"layer 1 enter", lines.releaseEnter, 30 * shedMiB},
		{"layer 1 leave", lines.releaseExit, 25 * shedMiB},
		{"layer 2 enter", lines.paceEnter, 40 * shedMiB},
		{"layer 2 leave", lines.paceExit, 35 * shedMiB},
		{"layer 3", lines.shed, 45 * shedMiB},
		{"layer 3 exit", lines.shedExit, 42*shedMiB + 512<<10},
		{"hard line", lines.hard, 49 * shedMiB},
	} {
		if check.got != check.want {
			t.Fatalf("%s at %d MiB, want %d MiB", check.name, check.got/shedMiB, check.want/shedMiB)
		}
	}
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	if lines.shed != thresholds.trigger || lines.paceEnter != thresholds.armed || lines.releaseEnter != thresholds.resume {
		t.Fatal("the layers no longer sit on the threshold machine's own lines")
	}
}

func TestLayersHaveHysteresis(t *testing.T) {
	lines := limitLines()
	var ladder shedLadder
	now := time.Unix(0, 0)
	step := func(usageMiB uint64) shedStep {
		now = now.Add(time.Second)
		return ladder.step(lines, atUsage(usageMiB*shedMiB), false, now)
	}
	if out := step(29); out.release || out.pace || out.shed {
		t.Fatalf("29 MiB acted: %+v", out)
	}
	if out := step(30); !out.release || !out.releaseChanged || !out.freeMemory || out.pace {
		t.Fatalf("30 MiB must enter layer 1 and release once: %+v", out)
	}
	if out := step(26); !out.release || out.releaseChanged || out.freeMemory {
		t.Fatalf("26 MiB must stay in layer 1 without releasing again: %+v", out)
	}
	if out := step(40); !out.pace || !out.paceChanged {
		t.Fatalf("40 MiB must enter layer 2: %+v", out)
	}
	if out := step(36); !out.pace {
		t.Fatalf("36 MiB left layer 2 above its exit line: %+v", out)
	}
	if out := step(34); out.pace || !out.paceChanged || !out.release {
		t.Fatalf("34 MiB must leave layer 2 and stay in layer 1: %+v", out)
	}
	if out := step(24); out.release || !out.releaseChanged {
		t.Fatalf("24 MiB must leave layer 1: %+v", out)
	}
}

func TestLayerOneReleaseIsRateLimited(t *testing.T) {
	lines := limitLines()
	start := time.Unix(0, 0)
	count := func(usageAt func(second int) uint64) int {
		var ladder shedLadder
		releases := 0
		for second := 0; second < 31; second++ {
			if ladder.step(lines, atUsage(usageAt(second)), false, start.Add(time.Duration(second)*time.Second)).freeMemory {
				releases++
			}
		}
		return releases
	}
	if got := count(func(int) uint64 { return 32 * shedMiB }); got != 1 {
		t.Fatalf("31 s at a steady 32 MiB released %d times, want 1", got)
	}
	if got := count(func(second int) uint64 { return 31*shedMiB + uint64(second/2)*shedMiB }); got != 4 {
		t.Fatalf("31 s of growth released %d times, want 4 (every 10 s)", got)
	}
	var ladder shedLadder
	releases := 0
	for second := 0; second < 31; second++ {
		sample := atUsage(36 * shedMiB)
		sample.connections = 70
		if second >= 15 {
			sample.connections = 50
		}
		if ladder.step(lines, sample, false, start.Add(time.Duration(second)*time.Second)).freeMemory {
			releases++
		}
	}
	if releases != 2 {
		t.Fatalf("closing twenty connections released %d times in 31 s, want 2", releases)
	}
}

func TestShedEpisodesCoolDownAndBackOff(t *testing.T) {
	lines := limitLines()
	var ladder shedLadder
	now := time.Unix(1000, 0)
	if out := ladder.step(lines, atUsage(45*shedMiB), false, now); !out.shed || !out.mayClose {
		t.Fatalf("45 MiB must start an episode that may close: %+v", out)
	}
	if !ladder.step(lines, atUsage(20*shedMiB), true, now).shed {
		t.Fatal("a predicted crossing must start an episode")
	}
	var waits []time.Duration
	for i := 0; i < 8; i++ {
		ladder.episodeDone(shedEpisodeResult{reason: shedReasonNoCandidate}, now)
		waits = append(waits, ladder.cooldownUntil.Sub(now))
		if ladder.step(lines, atUsage(46*shedMiB), false, now.Add(ladder.cooldownUntil.Sub(now)-time.Millisecond)).shed {
			t.Fatalf("an episode started inside its cooldown (%v)", waits)
		}
	}
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60, 60}
	for i := range want {
		if waits[i] != want[i]*time.Second {
			t.Fatalf("cooldowns %v, want %v seconds", waits, want)
		}
	}
}

var shedNotPaid = shedEpisodeResult{closed: 4, reason: shedReasonTooLittle}

func mayCloseAt(ladder *shedLadder, usage uint64, at time.Time) bool {
	out := ladder.step(limitLines(), atUsage(usage), false, at)
	return out.shed && out.mayClose
}

func TestClosesThatDoNotPayTwiceInARowHoldClosingOff(t *testing.T) {
	now := time.Unix(1000, 0)
	var ladder shedLadder
	ladder.episodeDone(shedNotPaid, now)
	if !mayCloseAt(&ladder, 46*shedMiB, now.Add(shedCooldown)) {
		t.Fatal("one episode whose closes did not pay held closing off")
	}
	var waits []time.Duration
	for i := 0; i < 5; i++ {
		ladder.episodeDone(shedNotPaid, now)
		waits = append(waits, ladder.closeAfter.Sub(now))
		if mayCloseAt(&ladder, 46*shedMiB, ladder.closeAfter.Add(-time.Millisecond)) {
			t.Fatalf("an episode may close inside its close backoff (%v)", waits)
		}
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("close backoffs %v, want %v", waits, want)
		}
	}
	ladder.episodeDone(shedEpisodeResult{reason: shedReasonReleased}, now)
	if got := ladder.closeAfter.Sub(now); got != time.Minute {
		t.Fatalf("a release-only episode moved the close backoff to %v", got)
	}
	ladder.episodeDone(shedEpisodeResult{closed: 4, closesPaid: true, reason: shedReasonUnderLine}, now)
	if got := ladder.cooldownUntil.Sub(now); got != shedCooldown || !ladder.closeAfter.IsZero() {
		t.Fatalf("closes that paid left a %v cooldown and closeAfter %v, want the base and none", got, ladder.closeAfter)
	}
	ladder.episodeDone(shedNotPaid, now)
	if !ladder.closeAfter.IsZero() {
		t.Fatal("after closes that paid, a single episode that did not pay held closing off")
	}

	var under shedLadder
	under.episodeDone(shedNotPaid, now)
	under.episodeDone(shedNotPaid, now)
	under.step(limitLines(), atUsage(43*shedMiB), false, now.Add(time.Second))
	if under.closeAfter.IsZero() {
		t.Fatal("43 MiB is not under layer 3's exit line, yet the close backoff was dropped")
	}
	under.step(limitLines(), atUsage(42*shedMiB), false, now.Add(time.Second))
	if !under.closeAfter.IsZero() || under.closeBackoff != 0 {
		t.Fatalf("42 MiB is under layer 3's exit line; the close backoff is still %v", under.closeBackoff)
	}
	under.episodeDone(shedNotPaid, now)
	if !under.closeAfter.IsZero() {
		t.Fatal("under the exit line, the run of episodes that did not pay should have started over")
	}
}

func TestLeavingLayerTwoStartsLayerThreeOver(t *testing.T) {
	now := time.Unix(1000, 0)
	var ladder shedLadder
	ladder.step(limitLines(), atUsage(41*shedMiB), false, now)
	for i := 0; i < 3; i++ {
		ladder.episodeDone(shedEpisodeResult{reason: shedReasonNoCandidate}, now)
	}
	ladder.episodeDone(shedNotPaid, now)
	ladder.episodeDone(shedNotPaid, now)
	ladder.step(limitLines(), atUsage(34*shedMiB), false, now.Add(time.Second))
	if !mayCloseAt(&ladder, 46*shedMiB, now.Add(time.Second+100*time.Millisecond)) {
		t.Fatalf("leaving layer 2 left layer 3 waiting: cooldown until %v, closing after %v", ladder.cooldownUntil.Sub(now), ladder.closeAfter.Sub(now))
	}
}

func TestANodeResetWaitsForItsMemory(t *testing.T) {
	now := time.Unix(1000, 0)
	var ladder shedLadder
	ladder.episodeDone(shedNotPaid, now)
	ladder.episodeDone(shedNotPaid, now)
	ladder.episodeDone(shedEpisodeResult{closed: 20, nodesReset: 1, closesPaid: true, reason: shedReasonNodeReset}, now)
	if !ladder.closeAfter.IsZero() || ladder.closeBackoff != 0 {
		t.Fatalf("a node reset left the close backoff at %v", ladder.closeBackoff)
	}
	if ladder.step(limitLines(), atUsage(46*shedMiB), false, now.Add(shedNodeResetWait-100*time.Millisecond)).shed {
		t.Fatal("an episode started while the reset node's memory was still coming back")
	}
	if !mayCloseAt(&ladder, 46*shedMiB, now.Add(shedNodeResetWait)) {
		t.Fatalf("no episode %v after a node reset", shedNodeResetWait)
	}
}

func TestTheHardLineIgnoresTheBackoffs(t *testing.T) {
	now := time.Unix(1000, 0)
	var ladder shedLadder
	for i := 0; i < 5; i++ {
		ladder.episodeDone(shedEpisodeResult{reason: shedReasonNoCandidate}, now)
	}
	if ladder.step(limitLines(), atUsage(48*shedMiB), false, now.Add(shedCooldown)).shed {
		t.Fatal("below the hard line the cooldown must hold")
	}
	if ladder.step(limitLines(), atUsage(49*shedMiB), false, now.Add(shedCooldown-time.Millisecond)).shed {
		t.Fatal("two episodes less than 2 s apart at the hard line")
	}
	if !ladder.step(limitLines(), atUsage(49*shedMiB), false, now.Add(shedCooldown)).shed {
		t.Fatal("the hard line waited out a backed-off cooldown")
	}
	var reset shedLadder
	reset.episodeDone(shedEpisodeResult{closed: 20, nodesReset: 1, closesPaid: true, reason: shedReasonNodeReset}, now)
	if !reset.step(limitLines(), atUsage(49*shedMiB), false, now.Add(shedCooldown)).shed {
		t.Fatal("the hard line waited out a node reset's wait")
	}

	f := newFakeEpisode(100, 49*shedMiB+512<<10, 300<<10)
	if result := runShedEpisode(limitLines(), f.deps(), false); len(f.closed) == 0 {
		t.Fatalf("at the hard line the close backoff held: %+v", result)
	}
	g := newFakeEpisode(100, 48*shedMiB+512<<10, 300<<10)
	if result := runShedEpisode(limitLines(), g.deps(), false); len(g.closed) != 0 || result.reason != shedReasonCloseBackoff {
		t.Fatalf("below the hard line the close backoff must hold: closed %d (%+v)", len(g.closed), result)
	}
}

type fakeEpisode struct {
	usage   uint64
	freePer uint64
	conns   []shedCandidate
	closed  []string
	frees   int
	settles int
	samples []uint64
	stopAt  int
	resets  []string
}

func newFakeEpisode(n int, usage, freePer uint64) *fakeEpisode {
	f := &fakeEpisode{usage: usage, freePer: freePer}
	for i := 0; i < n; i++ {
		f.conns = append(f.conns, shedCandidate{shedView: shedView{id: fmt.Sprintf("c%03d", i)}, weight: max(int64(freePer), shedTCPBaseBytes) + int64(n-i)})
	}
	return f
}

func (f *fakeEpisode) deps() shedEpisodeDeps {
	return shedEpisodeDeps{
		sample: func() pressureSample {
			f.samples = append(f.samples, f.usage)
			return atUsage(f.usage)
		},
		candidates: func() []shedCandidate {
			var open []shedCandidate
			for _, c := range f.conns {
				gone := false
				for _, id := range f.closed {
					gone = gone || id == c.id
				}
				if !gone {
					open = append(open, c)
				}
			}
			return open
		},
		closeOne: func(c shedCandidate) {
			f.closed = append(f.closed, c.id)
			f.usage -= f.freePer
		},
		free:      func() { f.frees++ },
		resetNode: func(node string) { f.resets = append(f.resets, node) },
		settle: func(d time.Duration) bool {
			f.settles++
			if d != shedSettle {
				panic("settle")
			}
			return f.stopAt == 0 || f.settles < f.stopAt
		},
	}
}

func TestAnEpisodeStopsBackUnderTheLine(t *testing.T) {
	f := newFakeEpisode(100, 47*shedMiB, 300<<10)
	result := runShedEpisode(limitLines(), f.deps(), true)
	if !result.closesPaid || result.reason != shedReasonUnderLine {
		t.Fatalf("result %+v", result)
	}
	if len(f.closed) != 8 || f.frees != 3 || f.settles != 2 {
		t.Fatalf("closed %d in %d releases/%d settles, want 8 after the opening release and 2 more", len(f.closed), f.frees, f.settles)
	}
	for i, id := range f.closed {
		if id != fmt.Sprintf("c%03d", i) {
			t.Fatalf("closed %v; the heaviest go first", f.closed)
		}
	}
}

func TestAnEpisodeNeverClosesMoreThanAQuarter(t *testing.T) {
	f := newFakeEpisode(40, 60*shedMiB, shedMiB)
	result := runShedEpisode(limitLines(), f.deps(), true)
	if result.reason != shedReasonCap || len(f.closed) != 10 || result.present != 40 {
		t.Fatalf("closed %d of 40 (%+v), want 10", len(f.closed), result)
	}
	if result.ineffective() {
		t.Fatal("an episode whose batches kept paying is not ineffective")
	}
}

func TestAnEpisodeStopsWhenABatchDoesNotPay(t *testing.T) {
	f := newFakeEpisode(400, 48*shedMiB, 10<<10)
	result := runShedEpisode(limitLines(), f.deps(), true)
	if result.reason != shedReasonTooLittle || len(f.closed) != shedBatch {
		t.Fatalf("closed %d (%+v), want one batch of %d", len(f.closed), result, shedBatch)
	}
	if !result.ineffective() {
		t.Fatal("not marked ineffective")
	}
}

func TestAStalledGroupIsShedWhole(t *testing.T) {
	f := newFakeEpisode(70, 48*shedMiB, 120<<10)
	for i := 0; i < 30; i++ {
		f.conns[i].network, f.conns[i].queuedKnown, f.conns[i].queued, f.conns[i].sinceDownload = C.TCP, true, 64<<10, time.Minute
		f.conns[i].group = "HY2"
	}
	result := runShedEpisode(limitLines(), f.deps(), true)
	if len(f.closed) != 30 || f.settles != 1 {
		t.Fatalf("closed %d in %d batches (%+v), want the 30 stalled flows in one", len(f.closed), f.settles, result)
	}
	for _, id := range f.closed {
		if id >= "c030" {
			t.Fatalf("closed %s, a flow that was still moving", id)
		}
	}
	if !result.closesPaid || result.reason != shedReasonNodeReset {
		t.Fatalf("a wedged node shed whole counts as paying: %+v", result)
	}
	if len(f.resets) != 1 || f.resets[0] != "HY2" || result.nodesReset != 1 {
		t.Fatalf("node resets %v (%d), want the wedged node once, after its flows", f.resets, result.nodesReset)
	}
}

func TestAWedgedGroupEndsItsEpisode(t *testing.T) {
	f := newFakeEpisode(40, 60*shedMiB, shedMiB)
	f.freePer = 0
	for i := 0; i < 8; i++ {
		f.conns[i].network, f.conns[i].queuedKnown, f.conns[i].queued, f.conns[i].sinceDownload = C.TCP, true, 64<<10, time.Minute
		f.conns[i].group = "TUIC"
	}
	result := runShedEpisode(limitLines(), f.deps(), true)
	if len(f.closed) != 8 || result.reason != shedReasonNodeReset || !result.closesPaid || len(f.resets) != 1 {
		t.Fatalf("closed %d, resets %v (%+v); want the group of 8, its node reset, and the episode over", len(f.closed), f.resets, result)
	}
	f.freePer = shedMiB
	result = runShedEpisode(limitLines(), f.deps(), true)
	if result.reason != shedReasonCap || len(f.closed) != 8+8 {
		t.Fatalf("closed %d in all (%+v), want the group of 8 and then a quarter of the 32 left", len(f.closed), result)
	}
}

func TestABatchPaysWhenItGivesBackHalfItsWeight(t *testing.T) {
	for _, c := range []struct {
		weight, freePer int64
		paid            bool
	}{
		{shedTCPBaseBytes, shedTCPBaseBytes, true},
		{shedTCPBaseBytes, shedTCPBaseBytes / 2, true},
		{shedTCPBaseBytes, shedTCPBaseBytes/2 - 1, false},
		{1 << 20, 300 << 10, false},
	} {
		f := newFakeEpisode(100, 48*shedMiB, uint64(c.freePer))
		for i := range f.conns {
			f.conns[i].weight = c.weight
		}
		result := runShedEpisode(limitLines(), f.deps(), true)
		if result.closesPaid != c.paid {
			t.Fatalf("weight %d, %d back a flow: paid=%v (%+v), want %v", c.weight, c.freePer, result.closesPaid, result, c.paid)
		}
		if !c.paid && (result.reason != shedReasonTooLittle || len(f.closed) != shedBatch) {
			t.Fatalf("weight %d, %d back a flow: closed %d (%+v); a batch that does not pay ends the episode", c.weight, c.freePer, len(f.closed), result)
		}
	}
}

func TestNothingIsClosedWhenTheConnectionsCannotCoverTheExcess(t *testing.T) {
	f := newFakeEpisode(20, 48*shedMiB, 57<<10)
	for i := range f.conns {
		f.conns[i].weight = 57 << 10
	}
	result := runShedEpisode(limitLines(), f.deps(), true)
	if result.reason != shedReasonNotInConnections || len(f.closed) != 0 || !result.ineffective() {
		t.Fatalf("closed %d (%+v)", len(f.closed), result)
	}
	g := newFakeEpisode(20, 45*shedMiB+512<<10, 300<<10)
	for i := range g.conns {
		g.conns[i].weight = 57 << 10
	}
	if result := runShedEpisode(limitLines(), g.deps(), true); len(g.closed) == 0 {
		t.Fatalf("an excess the connections can cover closed nothing: %+v", result)
	}
}

func TestAnEpisodeEndsWhenTheMonitorStops(t *testing.T) {
	f := newFakeEpisode(100, 48*shedMiB, 300<<10)
	f.stopAt = 1
	if result := runShedEpisode(limitLines(), f.deps(), true); result.reason != shedReasonStopped || len(f.closed) != shedBatch {
		t.Fatalf("result %+v after %d closed", result, len(f.closed))
	}
}

func TestTheQuarterRoundsUp(t *testing.T) {
	f := newFakeEpisode(3, 48*shedMiB, 0)
	for i := range f.conns {
		f.conns[i].weight = 1 << 20
	}
	result := runShedEpisode(limitLines(), f.deps(), true)
	if len(f.closed) != 1 || result.reason != shedReasonTooLittle {
		t.Fatalf("closed %d of 3 (%+v), want 1", len(f.closed), result)
	}
	empty := newFakeEpisode(0, 48*shedMiB, 0)
	if result := runShedEpisode(limitLines(), empty.deps(), true); result.reason != shedReasonNoCandidate || result.closed != 0 || empty.frees != 1 {
		t.Fatalf("no connections: %+v after %d releases; nothing to close still releases once", result, empty.frees)
	}
}
