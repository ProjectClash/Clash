package clash

import (
	"runtime/debug"
	"runtime/metrics"
	"time"

	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const (
	quietReleasePeriod    = 30 * time.Second
	quietReleaseFreeBytes = 512 << 10
)

type quietRelease struct {
	total      int64
	quietSince time.Time
	released   bool
	traffic    func() int64
	free       func() uint64
	release    func()
}

func newQuietRelease(now time.Time) *quietRelease {
	q := &quietRelease{quietSince: now, traffic: coreTrafficTotal, free: heapFreeBytes, release: debug.FreeOSMemory}
	q.total = q.traffic()
	return q
}

func coreTrafficTotal() int64 {
	up, down := statistic.DefaultManager.Total()
	return up + down
}

const heapFreeMetric = "/memory/classes/heap/free:bytes"

func heapFreeBytes() uint64 {
	sample := []metrics.Sample{{Name: heapFreeMetric}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

func (q *quietRelease) observe(now time.Time) bool {
	if total := q.traffic(); total != q.total {
		q.total, q.quietSince, q.released = total, now, false
		return false
	}
	if q.released || now.Sub(q.quietSince) < quietReleasePeriod {
		return false
	}
	if q.free() < quietReleaseFreeBytes {
		return false
	}
	q.release()
	q.released = true
	return true
}
