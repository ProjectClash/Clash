package adapter

import (
	"slices"
	"strings"
	"sync/atomic"

	"github.com/ProjectClash/Clash/common/queue"
	C "github.com/ProjectClash/Clash/constant"
)

type nodeHistory struct {
	queue atomic.Pointer[queue.Queue[C.DelayHistory]]
}

func (h *nodeHistory) made() *queue.Queue[C.DelayHistory] {
	if q := h.queue.Load(); q != nil {
		return q
	}
	h.queue.CompareAndSwap(nil, queue.New[C.DelayHistory](defaultHistoriesNum))
	return h.queue.Load()
}

func (h *nodeHistory) Put(items ...C.DelayHistory) {
	h.made().Put(items...)
}

func (h *nodeHistory) Pop() (head C.DelayHistory) {
	if q := h.queue.Load(); q != nil {
		return q.Pop()
	}
	return head
}

func (h *nodeHistory) Last() (last C.DelayHistory) {
	if q := h.queue.Load(); q != nil {
		return q.Last()
	}
	return last
}

func (h *nodeHistory) Copy() []C.DelayHistory {
	if q := h.queue.Load(); q != nil {
		return q.Copy()
	}
	return nil
}

func (h *nodeHistory) Len() int64 {
	if q := h.queue.Load(); q != nil {
		return q.Len()
	}
	return 0
}

func (p *Proxy) LastDelay() (record C.DelayHistory, ok bool) {
	if p.history.Len() == 0 {
		return record, false
	}
	return p.history.Last(), true
}

type DelaySnapshot struct {
	Alive    bool
	Measured bool
	Record   C.DelayHistory
	Failure  *URLTestFailure
}

type URLDelay struct {
	URL      string
	Alive    bool
	Recorded bool
	Record   C.DelayHistory
	Failure  *URLTestFailure
}

func (p *Proxy) LastRecord() (record C.DelayHistory, failure *URLTestFailure, ok bool) {
	p.records.Lock()
	defer p.records.Unlock()
	if p.history.Len() == 0 {
		return record, nil, false
	}
	return p.history.Last(), p.failure.Load(), true
}

func (p *Proxy) AppendURLDelays(dst []URLDelay) []URLDelay {
	p.records.Lock()
	defer p.records.Unlock()
	return p.appendURLDelays(dst)
}

func (p *Proxy) DelaySnapshot(dst []URLDelay) (DelaySnapshot, []URLDelay) {
	p.records.Lock()
	defer p.records.Unlock()
	snapshot := DelaySnapshot{Alive: p.AliveForTestUrl("")}
	if p.history.Len() > 0 {
		snapshot.Measured, snapshot.Record, snapshot.Failure = true, p.history.Last(), p.failure.Load()
	}
	return snapshot, p.appendURLDelays(dst)
}

func (p *Proxy) appendURLDelays(dst []URLDelay) []URLDelay {
	start := len(dst)
	p.extra.mu.RLock()
	for url, state := range p.extra.states {
		dst = append(dst, URLDelay{URL: url, Alive: state.alive.Load(), Recorded: state.history.Len() > 0, Record: state.history.Last(), Failure: state.failure.Load()})
	}
	p.extra.mu.RUnlock()
	slices.SortFunc(dst[start:], func(a, b URLDelay) int { return strings.Compare(a.URL, b.URL) })
	return dst
}
