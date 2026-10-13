package clash

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

const (
	shedPaceRate    = 8
	shedPaceBurst   = 8
	shedPaceMaxWait = 5 * time.Second
)

type sessionPacer struct {
	active atomic.Bool

	mu       sync.Mutex
	released chan struct{}
	tat      time.Time

	interval time.Duration
	burst    int
	maxWait  time.Duration
	now      func() time.Time
	timer    func(time.Duration) (<-chan time.Time, func() bool)

	paced       atomic.Uint64
	pacedNanos  atomic.Uint64
	reachedMax  atomic.Uint64
	activations atomic.Uint64
}

func newSessionPacer() *sessionPacer {
	return &sessionPacer{
		released: make(chan struct{}),
		interval: time.Second / shedPaceRate,
		burst:    shedPaceBurst,
		maxWait:  shedPaceMaxWait,
		now:      time.Now,
		timer: func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		},
	}
}

func (p *sessionPacer) setActive(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active.Load() == on {
		return
	}
	p.active.Store(on)
	if on {
		p.activations.Add(1)
		p.tat = time.Time{}
		return
	}
	close(p.released)
	p.released = make(chan struct{})
}

func (p *sessionPacer) wait(ctx context.Context, network C.NetWork) {
	if !p.active.Load() {
		return
	}
	p.mu.Lock()
	if !p.active.Load() {
		p.mu.Unlock()
		return
	}
	now := p.now()
	tat := p.tat
	if tat.Before(now) {
		tat = now
	}
	depart := tat.Add(-time.Duration(p.burst-1) * p.interval)
	delay := depart.Sub(now)
	capped := delay > p.maxWait
	if capped {
		delay = p.maxWait
	} else {
		p.tat = tat.Add(p.interval)
	}
	released := p.released
	p.mu.Unlock()

	if delay <= 0 {
		return
	}
	fire, stop := p.timer(delay)
	defer stop()
	start := p.now()
	select {
	case <-fire:
		if capped {
			p.reachedMax.Add(1)
		}
	case <-released:
	case <-ctx.Done():
	}
	waited := p.now().Sub(start)
	p.paced.Add(1)
	p.pacedNanos.Add(uint64(waited))
	if waited >= time.Second {
		log.Debugln("[Memory] paced a new %s session for %s", network, waited.Round(time.Millisecond))
	}
}

const shedRoundMaxHold = time.Minute

type roundHold struct {
	mu      sync.Mutex
	held    bool
	release chan struct{}
	maxHold time.Duration

	holds   atomic.Uint64
	expired atomic.Uint64
}

func newRoundHold() *roundHold {
	return &roundHold{release: make(chan struct{}), maxHold: shedRoundMaxHold}
}

func (h *roundHold) set(held bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held == held {
		return
	}
	h.held = held
	if !held {
		close(h.release)
		h.release = make(chan struct{})
	}
}

func (h *roundHold) wait(ctx context.Context) error {
	h.mu.Lock()
	held, release := h.held, h.release
	h.mu.Unlock()
	if !held {
		return nil
	}
	h.holds.Add(1)
	timer := time.NewTimer(h.maxHold)
	defer timer.Stop()
	select {
	case <-release:
		return nil
	case <-timer.C:
		h.expired.Add(1)
		log.Infoln("[Memory] a background test round waited %s for memory and runs anyway", h.maxHold)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
