package tun

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

type DeferredHandshakeHandler interface {
	DeferHandshake(network string, source M.Socksaddr, destination M.Socksaddr) bool
}

const deferredHandshakeBudget = 128

var deferredHandshakeVerdict atomic.Int64

func init() { deferredHandshakeVerdict.Store(int64(30 * time.Second)) }

func deferredHandshakeVerdictWait() time.Duration {
	return time.Duration(deferredHandshakeVerdict.Load())
}

func deferredHandshakeVerdictForTest(d time.Duration) func() {
	previous := deferredHandshakeVerdict.Swap(int64(d))
	return func() { deferredHandshakeVerdict.Store(previous) }
}

var deferredHandshakesInFlight atomic.Int32

func acquireDeferredHandshake() bool {
	if deferredHandshakesInFlight.Add(1) > deferredHandshakeBudget {
		deferredHandshakesInFlight.Add(-1)
		deferredStats.budgetSpent.Add(1)
		return false
	}
	deferredStats.deferred.Add(1)
	return true
}

type DeferredHandshakeReport struct {
	Deferred, BudgetSpent uint64
	Completed, CompletedLate, NotCompleted uint64
	Refused uint64
	Pending int32
}

var deferredStats struct {
	deferred, budgetSpent, completed, completedLate, notCompleted, refused atomic.Uint64
}

func DeferredHandshakeSnapshot() DeferredHandshakeReport {
	return DeferredHandshakeReport{
		Deferred:      deferredStats.deferred.Load(),
		BudgetSpent:   deferredStats.budgetSpent.Load(),
		Completed:     deferredStats.completed.Load(),
		CompletedLate: deferredStats.completedLate.Load(),
		NotCompleted:  deferredStats.notCompleted.Load(),
		Refused:       deferredStats.refused.Load(),
		Pending:       deferredHandshakesInFlight.Load(),
	}
}

func resetDeferredHandshakeStatsForTest() {
	for _, counter := range []*atomic.Uint64{
		&deferredStats.deferred, &deferredStats.budgetSpent, &deferredStats.completed,
		&deferredStats.completedLate, &deferredStats.notCompleted, &deferredStats.refused,
	} {
		counter.Store(0)
	}
}

type deferredFlowGroup struct {
	closing chan struct{}

	mu    sync.Mutex
	cond  *sync.Cond
	shut  bool
	count int
}

func newDeferredFlowGroup() *deferredFlowGroup {
	group := &deferredFlowGroup{closing: make(chan struct{})}
	group.cond = sync.NewCond(&group.mu)
	return group
}

func (g *deferredFlowGroup) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.shut {
		return false
	}
	g.count++
	return true
}

func (g *deferredFlowGroup) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count--
	if g.count == 0 {
		g.cond.Broadcast()
	}
}

func (g *deferredFlowGroup) done() <-chan struct{} { return g.closing }

func (g *deferredFlowGroup) shutdown() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.shut {
		g.shut = true
		close(g.closing)
	}
	for g.count > 0 {
		g.cond.Wait()
	}
}

func releaseDeferredHandshake() {
	if deferredHandshakesInFlight.Add(-1) <= deferredHandshakeBudget/2 {
		deferredBudgetSpentReported.Store(false)
	}
}

var deferredBudgetSpentReported atomic.Bool

func noteDeferredBudgetSpent(ctx context.Context, handler Handler) {
	if deferredBudgetSpentReported.CompareAndSwap(false, true) {
		handler.NewError(ctx, E.New("deferred handshakes: ", deferredHandshakeBudget, " dials are already waiting for an answer, so new connections are answered before their dial until those finish"))
	}
}

func deferredHandshakesPending() int32 { return deferredHandshakesInFlight.Load() }

var deferredCompletionObserver atomic.Pointer[func(string)]

func SetDeferredCompletionObserver(observe func(string)) {
	if observe == nil {
		deferredCompletionObserver.Store(nil)
		return
	}
	deferredCompletionObserver.Store(&observe)
}

func noteDeferredCompletion(line string) {
	if observe := deferredCompletionObserver.Load(); observe != nil {
		(*observe)(line)
	}
}
