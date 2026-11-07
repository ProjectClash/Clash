//go:build with_low_memory

package net

import (
	"io"
	"testing"
)

type scriptedRelaySource struct {
	lengths    []int
	capacities []int
}

func (s *scriptedRelaySource) Read(p []byte) (int, error) {
	s.capacities = append(s.capacities, len(p))
	if len(s.lengths) == 0 {
		return 0, io.EOF
	}
	n := s.lengths[0]
	if n > len(p) {
		n = len(p)
	}
	s.lengths = s.lengths[1:]
	return n, nil
}

func TestARelayDirectionBurstsWhileTheFlowKeepsUp(t *testing.T) {
	const big = 1 << 20
	source := &scriptedRelaySource{lengths: []int{big, big, 9000, 100, big}}
	before := relayBurstsHeld.Load()
	n, err := relayCopy(io.Discard, source)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{lowMemoryRelayMTU, relayBurstMTU, relayBurstMTU, lowMemoryRelayMTU, lowMemoryRelayMTU, relayBurstMTU}
	if !equalInts(source.capacities, want) {
		t.Fatalf("read buffers = %v, want %v", source.capacities, want)
	}
	if wantN := int64(lowMemoryRelayMTU + relayBurstMTU + 9000 + 100 + lowMemoryRelayMTU); n != wantN {
		t.Fatalf("copied %d, want %d", n, wantN)
	}
	if held := relayBurstsHeld.Load() - before; held != 0 {
		t.Fatalf("%d burst blocks still held after the copy ended", held)
	}
}

func TestRelayBurstsShareOneBudget(t *testing.T) {
	slots := 0
	for acquireRelayBurst() {
		slots++
	}
	defer func() {
		for ; slots > 0; slots-- {
			releaseRelayBurst()
		}
	}()
	if want := relayBurstBudget / relayBurstMTU; slots != want {
		t.Fatalf("budget held %d blocks, want %d", slots, want)
	}
	const big = 1 << 20
	source := &scriptedRelaySource{lengths: []int{big, big, big}}
	if _, err := relayCopy(io.Discard, source); err != nil {
		t.Fatal(err)
	}
	for _, capacity := range source.capacities {
		if capacity != lowMemoryRelayMTU {
			t.Fatalf("read buffers = %v with the budget spent, want %d each", source.capacities, lowMemoryRelayMTU)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
