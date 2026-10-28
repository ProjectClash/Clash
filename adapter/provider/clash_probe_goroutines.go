package provider

import (
	"context"
	"sync"
	"sync/atomic"
)


var probeGoroutines probePlaces

type probePlaces struct {
	mu       sync.Mutex
	limit    int
	held     int
	waiting  []chan struct{}
	uncapped atomic.Bool
}

func init() { probeGoroutines.uncapped.Store(true) }

func SetProbeGoroutineLimit(limit int) {
	p := &probeGoroutines
	p.mu.Lock()
	defer p.mu.Unlock()
	if limit < 0 {
		limit = 0
	}
	p.limit = limit
	p.handOffLocked()
}

func (p *probePlaces) handOffLocked() {
	for len(p.waiting) != 0 && (p.limit == 0 || p.held < p.limit) {
		next := p.waiting[0]
		p.waiting[0] = nil
		p.waiting = p.waiting[1:]
		p.held++
		close(next)
	}
	if len(p.waiting) == 0 {
		p.waiting = nil
	}
	p.uncapped.Store(p.limit == 0 && len(p.waiting) == 0)
}

func acquireProbeGoroutine(ctx context.Context) (release func(), ok bool) {
	p := &probeGoroutines
	if p.uncapped.Load() {
		return func() {}, true
	}
	p.mu.Lock()
	if p.limit == 0 {
		p.mu.Unlock()
		return func() {}, true
	}
	if ctx.Err() != nil {
		p.mu.Unlock()
		return nil, false
	}
	if len(p.waiting) == 0 && p.held < p.limit {
		p.held++
		p.mu.Unlock()
		return p.releaser(), true
	}
	granted := make(chan struct{})
	p.waiting = append(p.waiting, granted)
	p.mu.Unlock()
	select {
	case <-granted:
		return p.releaser(), true
	case <-ctx.Done():
		p.mu.Lock()
		defer p.mu.Unlock()
		for i, waiter := range p.waiting {
			if waiter == granted {
				p.waiting = append(p.waiting[:i], p.waiting[i+1:]...)
				p.handOffLocked()
				return nil, false
			}
		}
		p.held--
		p.handOffLocked()
		return nil, false
	}
}

func (p *probePlaces) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			p.held--
			p.handOffLocked()
			p.mu.Unlock()
		})
	}
}

func ProbeGoroutinesHeldForTest() int {
	probeGoroutines.mu.Lock()
	defer probeGoroutines.mu.Unlock()
	return probeGoroutines.held
}

func ProbeGoroutineLimitForTest() int {
	probeGoroutines.mu.Lock()
	defer probeGoroutines.mu.Unlock()
	return probeGoroutines.limit
}

type roundSlots chan struct{}

func newRoundSlots(limit int) roundSlots { return make(roundSlots, limit) }

func (s roundSlots) acquire(ctx context.Context) (release func(), ok bool) {
	s <- struct{}{}
	place, ok := acquireProbeGoroutine(ctx)
	if !ok {
		<-s
		return nil, false
	}
	return func() { place(); <-s }, true
}
