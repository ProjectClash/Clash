package clash

import (
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"testing"
	"time"
)

func gcCycles() uint64 {
	sample := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

func gogc() int {
	sample := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	metrics.Read(sample)
	return int(sample[0].Value.Uint64())
}

var gcSink []byte

func churn(n int) {
	for i := 0; i < n>>16; i++ {
		gcSink = make([]byte, 64<<10)
	}
	gcSink = nil
}

func TestACompactCallOverASmallHeapCollectsRarely(t *testing.T) {
	previous := debug.SetGCPercent(100)
	t.Cleanup(func() { debug.SetGCPercent(previous) })
	runtime.GC()
	before := gcCycles()
	_, _ = withCompactHeap(func() (struct{}, error) {
		churn(512 << 20)
		return struct{}{}, nil
	})
	if cycles := gcCycles() - before; cycles > 24 {
		t.Fatalf("512 MiB of garbage over a small heap collected %d times", cycles)
	}
	if after := debug.SetGCPercent(previous); after != 100 {
		t.Fatalf("the percent after the call is %d, want the 100 before it", after)
	}
}

func TestACompactCallOverALargeHeapCollectsAtTwentyPercent(t *testing.T) {
	previous := debug.SetGCPercent(100)
	savedFloor := compactHeapFloor
	compactHeapFloor = 1 << 20
	t.Cleanup(func() { debug.SetGCPercent(previous); compactHeapFloor = savedFloor })
	live := make([][]byte, 0, 64)
	for i := 0; i < 64; i++ {
		live = append(live, make([]byte, 1<<20))
	}
	runtime.GC()
	var percent int
	_, _ = withCompactHeap(func() (struct{}, error) {
		percent = gogc()
		return struct{}{}, nil
	})
	runtime.KeepAlive(live)
	if percent != compactHeapPercent {
		t.Fatalf("over 64 MiB live with a 1 MiB floor the percent is %d, want %d", percent, compactHeapPercent)
	}
}

func TestACompactCallFollowsItsGrowingHeap(t *testing.T) {
	previous := debug.SetGCPercent(100)
	savedFloor := compactHeapFloor
	compactHeapFloor = 4 << 20
	t.Cleanup(func() { debug.SetGCPercent(previous); compactHeapFloor = savedFloor })
	runtime.GC()
	var percents []int
	_, _ = withCompactHeap(func() (struct{}, error) {
		var live [][]byte
		for i := 0; i < 64; i++ {
			live = append(live, make([]byte, 1<<20))
			churn(4 << 20)
		}
		runtime.GC()
		deadline := time.Now().Add(time.Second)
		for {
			p := gogc()
			percents = append(percents, p)
			if p == compactHeapPercent || time.Now().After(deadline) {
				break
			}
			time.Sleep(followLiveHeapEvery)
		}
		runtime.KeepAlive(live)
		return struct{}{}, nil
	})
	if last := percents[len(percents)-1]; last != compactHeapPercent {
		t.Fatalf("with 64 MiB live over a 4 MiB floor the percent stayed %v", percents)
	}
}

func TestACompactCallKeepsALowerPercent(t *testing.T) {
	previous := debug.SetGCPercent(10)
	t.Cleanup(func() { debug.SetGCPercent(previous) })
	var during int
	_, _ = withCompactHeap(func() (struct{}, error) {
		churn(64 << 20)
		time.Sleep(3 * followLiveHeapEvery)
		during = gogc()
		return struct{}{}, nil
	})
	if during != 10 {
		t.Fatalf("a call under a percent of 10 ran at %d", during)
	}
	if after := debug.SetGCPercent(10); after != 10 {
		t.Fatalf("after the call the percent is %d, want 10", after)
	}
}

func TestOverlappingCompactCallsRestoreThePercentOnce(t *testing.T) {
	previous := debug.SetGCPercent(100)
	t.Cleanup(func() { debug.SetGCPercent(previous) })
	outer := enterCompactHeap()
	inner := enterCompactHeap()
	inner()
	churn(16 << 20)
	if gogc() == 100 {
		t.Fatal("the inner call's return restored the percent while the outer one runs")
	}
	outer()
	time.Sleep(3 * followLiveHeapEvery)
	if after := debug.SetGCPercent(previous); after != 100 {
		t.Fatalf("after both calls the percent is %d, want 100", after)
	}
}
