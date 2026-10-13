package clash

import (
	"sync"
	"time"

	"github.com/ProjectClash/Clash/log"
)

const probeAdmissionLogInterval = 30 * time.Second

type probeAdmissionLogSummary struct {
	counts  [2][4]uint64
	maxWait time.Duration
	elapsed time.Duration
}

type probeAdmissionDiagnostics struct {
	mu      sync.Mutex
	last    time.Time
	pending probeAdmissionLogSummary
}

func (d *probeAdmissionDiagnostics) observe(now time.Time, waited time.Duration, verdict probeAdmissionVerdict, background bool) (probeAdmissionLogSummary, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	class := 0
	if background {
		class = 1
	}
	d.pending.counts[class][verdict]++
	if waited > d.pending.maxWait {
		d.pending.maxWait = waited
	}
	if !d.last.IsZero() && now.Sub(d.last) < probeAdmissionLogInterval {
		return probeAdmissionLogSummary{}, false
	}
	summary := d.pending
	if !d.last.IsZero() {
		summary.elapsed = now.Sub(d.last)
	}
	d.last = now
	d.pending = probeAdmissionLogSummary{}
	return summary, true
}

const probeAdmissionLogWait = 100 * time.Millisecond

func (d *probeAdmissionDiagnostics) record(waited time.Duration, verdict probeAdmissionVerdict, background bool, slots *probeSlots) {
	summary, emit := d.observe(time.Now(), waited, verdict, background)
	detail := log.Level() == log.DEBUG
	if !emit && !detail {
		return
	}
	interactive, backgroundInFlight, interactiveWaiting, backgroundWaiting := slots.counts()
	if detail {
		log.Debugln("[Memory] probe admission: waited %dms verdict=%d background=%t in_flight=%d/%d waiting=%d/%d",
			waited.Milliseconds(), verdict, background, interactive, backgroundInFlight, interactiveWaiting, backgroundWaiting)
	}
	if emit {
		c := summary.counts
		log.Infoln("[Memory] probe admission summary: window_ms=%d interactive_admitted=%d interactive_deferred=%d background_admitted=%d background_deferred=%d max_wait_ms=%d in_flight=%d/%d waiting=%d/%d background_cap=%d",
			summary.elapsed.Milliseconds(), c[0][probeAdmitted], c[0][probeDeferred], c[1][probeAdmitted], c[1][probeDeferred], summary.maxWait.Milliseconds(),
			interactive, backgroundInFlight, interactiveWaiting, backgroundWaiting, slots.cfg.backgroundCap())
	}
}
