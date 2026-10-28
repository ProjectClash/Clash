package tun

import (
	"testing"
	"time"
)

func TestTheWriteBatchFollowsTheLoad(t *testing.T) {
	allocated := 0
	now := time.Unix(1000, 0)
	b := newClashWriteBatch(64, func() []byte { allocated++; return make([]byte, 16) }, now)
	if len(b.buffers) != clashWriteBatchInitial || allocated != clashWriteBatchInitial {
		t.Fatalf("starts with %d buffers (%d allocated), want %d", len(b.buffers), allocated, clashWriteBatchInitial)
	}
	for _, want := range []int{8, 16, 32, 64, 64} {
		b.observe(len(b.buffers), now)
		if len(b.buffers) != want {
			t.Fatalf("after a full read: %d buffers, want %d", len(b.buffers), want)
		}
	}
	b.observe(32, now.Add(time.Minute))
	b.observe(1, now.Add(time.Minute+clashWriteBatchIdle-time.Second))
	if len(b.buffers) != 64 {
		t.Fatalf("shrank while busy: %d", len(b.buffers))
	}
	b.observe(1, now.Add(time.Minute+clashWriteBatchIdle))
	if len(b.buffers) != clashWriteBatchInitial {
		t.Fatalf("after a quiet while: %d buffers, want %d", len(b.buffers), clashWriteBatchInitial)
	}
	for i, buffer := range b.buffers[:cap(b.buffers)][clashWriteBatchInitial:] {
		if buffer != nil {
			t.Fatalf("dropped buffer %d is still referenced", i+clashWriteBatchInitial)
		}
	}
	small := newClashWriteBatch(2, func() []byte { return make([]byte, 16) }, now)
	small.observe(2, now)
	if len(small.buffers) != 2 {
		t.Fatalf("a batch of 2 holds %d", len(small.buffers))
	}
}
