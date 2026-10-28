package clash

import (
	"container/list"
	"context"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

const (
	probeInteractiveCap = 16
	probeNodeCountTTL   = 30 * time.Second
)

func probeBackgroundCap(int) int {
	return probeBackgroundTier
}

const probeBackgroundTier = 10

type probeAdmissionVerdict uint8

const (
	probeAdmitted probeAdmissionVerdict = iota
	probeForced
	probeCtxExpired
	probeDeferred
)

type probeAdmissionConfig struct {
	interactiveCap int
	backgroundCap  func() int
}

type probeSlots struct {
	cfg probeAdmissionConfig

	mu                  sync.Mutex
	interactiveInFlight int
	backgroundInFlight  int
	interactiveQueue    list.List
	backgroundQueue     list.List
}

type probeWaiter struct {
	ready   chan struct{}
	granted bool
}

func newProbeSlots(cfg probeAdmissionConfig) *probeSlots {
	return &probeSlots{cfg: cfg}
}

func (s *probeSlots) interactiveRoom() bool {
	return s.interactiveInFlight < s.cfg.interactiveCap
}

func (s *probeSlots) backgroundRoom() bool {
	return s.interactiveQueue.Len() == 0 &&
		s.interactiveInFlight+s.backgroundInFlight < s.cfg.backgroundCap()
}

func (s *probeSlots) dispatch() {
	for s.interactiveQueue.Len() > 0 && s.interactiveRoom() {
		waiter := s.interactiveQueue.Remove(s.interactiveQueue.Front()).(*probeWaiter)
		waiter.granted = true
		s.interactiveInFlight++
		close(waiter.ready)
	}
	for s.backgroundQueue.Len() > 0 && s.backgroundRoom() {
		waiter := s.backgroundQueue.Remove(s.backgroundQueue.Front()).(*probeWaiter)
		waiter.granted = true
		s.backgroundInFlight++
		close(waiter.ready)
	}
}

func (s *probeSlots) admit(ctx context.Context, background bool) (end func(), verdict probeAdmissionVerdict) {
	if ctx.Err() != nil {
		return nil, probeDeferred
	}
	s.mu.Lock()
	queue := &s.interactiveQueue
	room := queue.Len() == 0 && s.interactiveRoom()
	if background {
		queue = &s.backgroundQueue
		room = queue.Len() == 0 && s.backgroundRoom()
	}
	if room {
		if background {
			s.backgroundInFlight++
		} else {
			s.interactiveInFlight++
		}
		s.mu.Unlock()
		return s.releaser(background), probeAdmitted
	}
	waiter := &probeWaiter{ready: make(chan struct{})}
	element := queue.PushBack(waiter)
	s.mu.Unlock()

	select {
	case <-waiter.ready:
		return s.releaser(background), probeAdmitted
	case <-ctx.Done():
		s.mu.Lock()
		if waiter.granted {
			s.release(background)
		} else {
			queue.Remove(element)
			s.dispatch()
		}
		s.mu.Unlock()
		return nil, probeDeferred
	}
}

func (s *probeSlots) releaser(background bool) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.release(background)
			s.mu.Unlock()
		})
	}
}

func (s *probeSlots) release(background bool) {
	if background {
		s.backgroundInFlight--
	} else {
		s.interactiveInFlight--
	}
	s.dispatch()
}

func (s *probeSlots) counts() (interactive, background, interactiveWaiting, backgroundWaiting int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interactiveInFlight, s.backgroundInFlight, s.interactiveQueue.Len(), s.backgroundQueue.Len()
}

type probeNodeCounter struct {
	mu      sync.Mutex
	count   int
	counted time.Time
	ttl     time.Duration
	read    func() int
}

func (c *probeNodeCounter) nodes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counted.IsZero() || time.Since(c.counted) >= c.ttl {
		c.count, c.counted = c.read(), time.Now()
	}
	return c.count
}

func isGroupAdapter(adapterType C.AdapterType) bool {
	switch adapterType {
	case C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return true
	}
	return false
}

func liveNodeCount() int {
	seen := map[string]struct{}{}
	for name, proxy := range tunnel.Proxies() {
		if !isGroupAdapter(proxy.Type()) {
			seen[name] = struct{}{}
		}
	}
	libraries := runningNodeCount()
	for _, provider := range tunnel.Providers() {
		if provider.VehicleType() == P.Compatible {
			continue
		}
		list := provider.ProxyList()
		if _, ok := list.(C.ProxyLibrary); ok {
			libraries += list.Len()
			continue
		}
		for i := 0; i < list.Len(); i++ {
			if proxy := list.At(i); !isGroupAdapter(proxy.Type()) {
				seen[proxy.Name()] = struct{}{}
			}
		}
	}
	return len(seen) + libraries
}

func defaultProbeAdmissionConfig() probeAdmissionConfig {
	counter := &probeNodeCounter{ttl: probeNodeCountTTL, read: liveNodeCount}
	return probeAdmissionConfig{
		interactiveCap: probeInteractiveCap,
		backgroundCap:  func() int { return probeBackgroundCap(counter.nodes()) },
	}
}

func probeAdmissionShouldArm(budgetedPlatform, underNetworkExtension bool) bool {
	return budgetedPlatform && underNetworkExtension
}

func armProbeAdmission() {
	cfg := defaultProbeAdmissionConfig()
	adapter.SetURLTestGate(newProbeAdmissionHook(cfg))
	provider.SetRoundConcurrency(cfg.backgroundCap)
	provider.SetProbeGoroutineLimit(probeGoroutinesPerBackgroundPlace * probeBackgroundTier)
}

const probeGoroutinesPerBackgroundPlace = 3

func disarmProbeAdmission() {
	adapter.SetURLTestAdmission(nil)
	provider.SetRoundConcurrency(nil)
	provider.SetProbeGoroutineLimit(0)
}

var probeAdmissionCounts atomic.Pointer[func() (int, int, int, int)]

func newProbeAdmissionHook(cfg probeAdmissionConfig) func(context.Context) (func(), error) {
	slots := newProbeSlots(cfg)
	counts := slots.counts
	probeAdmissionCounts.Store(&counts)
	var diagnostics probeAdmissionDiagnostics
	settler := &probeSettler{quiet: probeSettleQuiet}
	return func(ctx context.Context) (func(), error) {
		background := adapter.IsBackgroundProbe(ctx)
		start := time.Now()
		end, verdict := slots.admit(ctx, background)
		waited := time.Since(start)
		if waited >= probeAdmissionLogWait || verdict == probeDeferred {
			diagnostics.record(waited, verdict, background, slots)
		}
		if verdict == probeDeferred {
			return nil, adapter.ErrURLTestDeferred
		}
		settler.began()
		var once sync.Once
		return func() {
			if end != nil {
				end()
			}
			once.Do(settler.ended)
		}, nil
	}
}

var probeSettleQuiet = 3 * time.Second

type probeSettler struct {
	mu       sync.Mutex
	quiet    time.Duration
	inflight int
	ran      int
	timer    *time.Timer
	epoch    uint64
}

const probeSettleFloor = 8

func (s *probeSettler) began() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inflight++
	s.ran++
	s.epoch++
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}

func (s *probeSettler) ended() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inflight--
	if s.inflight == 0 && s.ran >= probeSettleFloor {
		s.epoch++
		epoch := s.epoch
		s.timer = time.AfterFunc(s.quiet, func() { s.settle(epoch) })
	}
}

func (s *probeSettler) settle(epoch uint64) {
	s.mu.Lock()
	if s.inflight > 0 || s.ran < probeSettleFloor || s.epoch != epoch {
		s.mu.Unlock()
		return
	}
	s.ran, s.timer = 0, nil
	s.mu.Unlock()
	probeSettles.Add(1)
	runtime.GC()
	debug.FreeOSMemory()
}

var probeSettles atomic.Int64
