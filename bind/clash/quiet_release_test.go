package clash

import (
	"runtime/metrics"
	"testing"
	"time"
)

type quietReleaseProbe struct {
	traffic  int64
	free     uint64
	idle     int
	idleAsks int
	releases int
}

func (p *quietReleaseProbe) quiet(start time.Time) *quietRelease {
	return &quietRelease{total: p.traffic, quietSince: start,
		traffic: func() int64 { return p.traffic },
		free:    func() uint64 { return p.free },
		idle:    func() int { p.idleAsks++; given := p.idle; p.idle = 0; return given },
		release: func() { p.releases++; p.free = 0 }}
}

func TestQuietReleaseReleasesOncePerQuietSpell(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	p := &quietReleaseProbe{traffic: 100, free: quietReleaseFreeBytes}
	q := p.quiet(start)
	if q.observe(start.Add(quietReleasePeriod - time.Second)) {
		t.Fatal("released before the quiet lasted the period")
	}
	if !q.observe(start.Add(quietReleasePeriod)) || p.releases != 1 {
		t.Fatalf("a spell with free pages to give must release, released %d", p.releases)
	}
	for at := 2; at < 120; at++ {
		p.free += quietReleaseFreeBytes
		if q.observe(start.Add(time.Duration(at) * quietReleasePeriod)) {
			t.Fatalf("released again in the same spell at %d periods", at)
		}
	}
	p.traffic++
	resumed := start.Add(200 * quietReleasePeriod)
	if q.observe(resumed) || q.observe(resumed.Add(quietReleasePeriod-time.Second)) {
		t.Fatal("released during traffic or before the new spell lasted the period")
	}
	if !q.observe(resumed.Add(quietReleasePeriod)) || p.releases != 2 {
		t.Fatalf("the new spell must release in its turn, released %d", p.releases)
	}
}

func TestQuietReleaseWaitsForFreePagesWorthIt(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	p := &quietReleaseProbe{traffic: 100, free: quietReleaseFreeBytes - 1}
	q := p.quiet(start)
	if q.observe(start.Add(10 * quietReleasePeriod)) {
		t.Fatal("released pages under the threshold")
	}
	p.free = quietReleaseFreeBytes
	if !q.observe(start.Add(11 * quietReleasePeriod)) {
		t.Fatal("the spell did not release once its free pages reached the threshold")
	}
}

func TestQuietReleaseGivesBackIdleConnectionStorageOncePerSpell(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	p := &quietReleaseProbe{traffic: 100, free: quietReleaseFreeBytes / 2, idle: quietReleaseFreeBytes / 2}
	q := p.quiet(start)
	if q.observe(start.Add(quietReleasePeriod-time.Second)) || p.idleAsks != 0 {
		t.Fatalf("asked the connections %d times before the spell lasted the period", p.idleAsks)
	}
	if !q.observe(start.Add(quietReleasePeriod)) || p.releases != 1 || p.idleAsks != 1 {
		t.Fatalf("free pages plus the connections' storage reach the threshold: released %d, asked %d", p.releases, p.idleAsks)
	}
	for at := 2; at < 10; at++ {
		q.observe(start.Add(time.Duration(at) * quietReleasePeriod))
	}
	if p.idleAsks != 1 {
		t.Fatalf("asked the connections %d times in one spell, want once", p.idleAsks)
	}
	p.traffic++
	p.free, p.idle = 1, 1
	resumed := start.Add(100 * quietReleasePeriod)
	q.observe(resumed)
	for at := 1; at < 5; at++ {
		if q.observe(resumed.Add(time.Duration(at) * quietReleasePeriod)) {
			t.Fatal("released under the threshold")
		}
	}
	if p.idleAsks != 2 || p.releases != 1 {
		t.Fatalf("the second spell asked %d times and released %d, want once and none", p.idleAsks-1, p.releases-1)
	}
}

func TestQuietReleaseIsTheIOSFamilyTunnelsOnly(t *testing.T) {
	for _, tc := range []struct {
		profile runtimeProfile
		underNE bool
		want    bool
	}{
		{runtimeProfileIOSPacketTunnel, true, true},
		{runtimeProfileTVOSPacketTunnel, true, true},
		{runtimeProfileIOSPacketTunnel, false, false},
		{runtimeProfileMacOSPacketTunnel, true, false},
		{runtimeProfileMacOSApplication, false, false},
	} {
		if got := runtimePolicyFor(tc.profile, tc.underNE).releaseWhenQuiet; got != tc.want {
			t.Errorf("%s underNE=%v: releaseWhenQuiet=%v, want %v", tc.profile, tc.underNE, got, tc.want)
		}
	}
}

func TestQuietReleaseReadsMetricsTheRuntimeHas(t *testing.T) {
	kinds := map[string]metrics.ValueKind{}
	for _, d := range metrics.All() {
		kinds[d.Name] = d.Kind
	}
	for _, name := range []string{heapFreeMetric} {
		if kind, ok := kinds[name]; !ok || kind != metrics.KindUint64 {
			t.Errorf("runtime metric %s: present %v, kind %v; want a uint64", name, ok, kind)
		}
	}
}
