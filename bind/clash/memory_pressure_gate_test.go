package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/tunnel/statistic"
)

type pressureProbe struct {
	statistic.Tracker
	id     string
	closed int
}

func (p *pressureProbe) Close() error {
	p.closed++
	return nil
}

func (p *pressureProbe) ID() string { return p.id }

func newPressureProbe(t *testing.T, id string) *pressureProbe {
	t.Helper()
	probe := &pressureProbe{id: id}
	statistic.DefaultManager.Join(probe)
	t.Cleanup(func() { statistic.DefaultManager.Leave(probe) })
	return probe
}

func TestMemoryPressureNeverClosesConnections(t *testing.T) {
	startPressureThresholdMonitor(0, pressureThresholdShedEnabled.Load())
	cases := []struct {
		name      string
		footprint int64
		softLimit int64
		why       string
	}{
		{
			name:      "far below any budget",
			footprint: 18 << 20,
			softLimit: 50 << 20,
			why:       "the measured steady state of the iOS Extension",
		},
		{
			name:      "at the budget, which the narrowed gate shed on",
			footprint: 49 << 20,
			softLimit: 50 << 20,
			why:       "the narrowed gate fired here; sing-box still does not",
		},
		{
			name:      "over the budget",
			footprint: 60 << 20,
			softLimit: 50 << 20,
			why:       "exceeding it is jetsam's business, not ours to pre-empt by killing sessions",
		},
		{
			name:      "no budget configured, as the macOS profiles run",
			footprint: 2 << 30,
			softLimit: 0,
			why:       "sing-box reaches for its NE regime only under C.IsIos, so macOS has none",
		},
		{
			name:      "footprint unavailable",
			footprint: -1,
			softLimit: 50 << 20,
			why:       "acting without a measurement is what was removed, not a fallback for it",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			probe := newPressureProbe(t, "pressure-"+testCase.name)

			before := memoryPressureEventCount.Load()
			for i := 0; i < 4; i++ {
				handleMemoryPressureWith(testCase.footprint, testCase.softLimit)
			}

			if probe.closed != 0 {
				t.Fatalf("pressure closed the connection %d time(s) at footprint=%d softLimit=%d — %s",
					probe.closed, testCase.footprint, testCase.softLimit, testCase.why)
			}
			if got := memoryPressureEventCount.Load() - before; got != 4 {
				t.Fatalf("pressure event count rose by %d, want 4; that counter is the only "+
					"remaining signal that the episode happened at all", got)
			}
		})
	}
}

func TestTheProbeWouldSeeATeardown(t *testing.T) {
	probe := newPressureProbe(t, "pressure-observability")

	found := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		if tracker == statistic.Tracker(probe) {
			found = true
			_ = tracker.Close()
			return false
		}
		return true
	})

	if !found {
		t.Fatal("the probe is not reachable from statistic.DefaultManager.Range, which is the " +
			"registry the removed teardown walked; the no-teardown assertions would be vacuous")
	}
	if probe.closed != 1 {
		t.Fatalf("closing through the registry recorded %d closes, want 1", probe.closed)
	}
}

func TestPressureHandlingSurvivesAnEvidenceWriteFailure(t *testing.T) {
	if err := RecordMemoryPressureEvidence(); err == nil {
		t.Skip("evidence recording succeeds in this process, so there is no failure to arrange")
	}

	probe := newPressureProbe(t, "pressure-evidence-failure")
	before := memoryPressureEventCount.Load()
	handleMemoryPressureWith(18<<20, 50<<20)

	if got := memoryPressureEventCount.Load() - before; got != 1 {
		t.Fatalf("event count rose by %d, want 1: a failed evidence write must not abort "+
			"pressure handling", got)
	}
	if probe.closed != 0 {
		t.Fatalf("a failed evidence write led to %d connection close(s)", probe.closed)
	}
}
