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

type URLDelay struct {
	URL      string
	Alive    bool
	Recorded bool
	Record   C.DelayHistory
}

func (p *Proxy) AppendURLDelays(dst []URLDelay) []URLDelay {
	start := len(dst)
	p.extra.mu.RLock()
	for url, state := range p.extra.states {
		dst = append(dst, URLDelay{URL: url, Alive: state.alive.Load(), Recorded: state.history.Len() > 0, Record: state.history.Last()})
	}
	p.extra.mu.RUnlock()
	slices.SortFunc(dst[start:], func(a, b URLDelay) int { return strings.Compare(a.URL, b.URL) })
	return dst
}
