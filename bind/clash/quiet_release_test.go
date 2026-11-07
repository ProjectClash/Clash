package clash

import (
	"runtime/metrics"
	"testing"
	"time"
)

type quietReleaseProbe struct {
	traffic  int64
	free     uint64
	releases int
}

func (p *quietReleaseProbe) quiet(start time.Time) *quietRelease {
	return &quietRelease{total: p.traffic, quietSince: start,
		traffic: func() int64 { return p.traffic },
		free:    func() uint64 { return p.free },
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
