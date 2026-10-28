package tun

import "time"

const (
	clashWriteBatchInitial = 4
	clashWriteBatchIdle    = 30 * time.Second
)

type clashWriteBatch struct {
	buffers    [][]byte
	limit      int
	allocate   func() []byte
	lastActive time.Time
}

func newClashWriteBatch(limit int, allocate func() []byte, now time.Time) *clashWriteBatch {
	b := &clashWriteBatch{limit: limit, allocate: allocate, lastActive: now}
	b.resize(clashWriteBatchSmaller(clashWriteBatchInitial, limit))
	return b
}

func clashWriteBatchSmaller(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (b *clashWriteBatch) resize(n int) {
	for len(b.buffers) < n {
		b.buffers = append(b.buffers, b.allocate())
	}
	for i := n; i < len(b.buffers); i++ {
		b.buffers[i] = nil
	}
	b.buffers = b.buffers[:n]
}

func (b *clashWriteBatch) observe(n int, now time.Time) {
	size := len(b.buffers)
	switch {
	case n >= size && size < b.limit:
		b.resize(clashWriteBatchSmaller(2*size, b.limit))
		b.lastActive = now
	case 2*n >= size:
		b.lastActive = now
	case size > clashWriteBatchInitial && now.Sub(b.lastActive) >= clashWriteBatchIdle:
		b.resize(clashWriteBatchSmaller(clashWriteBatchInitial, b.limit))
		b.lastActive = now
	}
}
