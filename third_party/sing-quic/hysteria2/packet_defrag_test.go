package hysteria2

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/metacubex/sing/common/buf"
)

func testFragment(packetID uint16, fragmentID, fragmentTotal uint8, data []byte) *udpMessage {
	message := allocMessage()
	message.sessionID = 123
	message.packetID = packetID
	message.fragmentID = fragmentID
	message.fragmentTotal = fragmentTotal
	message.destination = "test:123"
	message.data = buf.As(data)
	return message
}

func feedForPayload(d *udpDefragger, m *udpMessage) (string, bool) {
	result := d.feed(m)
	if result == nil {
		return "", false
	}
	payload := string(result.data.Bytes())
	result.releaseMessage()
	return payload, true
}

func TestDefraggerMatchesTheOfficialVectors(t *testing.T) {
	type vector struct {
		name          string
		packetID      uint16
		fragmentID    uint8
		fragmentTotal uint8
		data          string
		want          string
		complete      bool
	}
	vectors := []vector{
		{"no frag", 987, 0, 1, "hello", "hello", true},
		{"frag 0 - 1/2", 987, 0, 2, "hello ", "", false},
		{"frag 0 - 2/2", 987, 1, 2, "moto", "hello moto", true},
		{"frag 1 - 1/3", 987, 0, 3, "deco", "", false},
		{"frag 1 - 2/3", 987, 1, 3, "*", "", false},
		{"frag 1 - 3/3", 987, 2, 3, "27", "deco*27", true},
		{"frag 2 - 1/2", 233, 1, 2, "shinsekai", "", false},
		{"frag 3 - 2/2", 244, 1, 2, "what???", "", false},
		{"frag 2 - 2/2", 233, 1, 2, " annaijo", "", false},
		{"invalid id", 233, 88, 2, "shinsekai", "", false},
		{"frag 2 - 1/2 re", 233, 0, 2, "shinsekai", "shinsekai annaijo", true},
	}
	d := newUDPDefragger()
	for _, v := range vectors {
		got, complete := feedForPayload(d, testFragment(v.packetID, v.fragmentID, v.fragmentTotal, []byte(v.data)))
		if complete != v.complete || got != v.want {
			t.Fatalf("%s: feed() = (%q, %v), want (%q, %v)", v.name, got, complete, v.want, v.complete)
		}
	}
}

func TestDefraggerReassemblesOutOfOrderFragmentsAndDropsDuplicates(t *testing.T) {
	d := newUDPDefragger()
	steps := []struct {
		packetID      uint16
		fragmentID    uint8
		fragmentTotal uint8
		data          string
		want          string
		complete      bool
	}{
		{7, 2, 3, "c", "", false},
		{7, 0, 3, "a", "", false},
		{7, 0, 3, "x", "", false},
		{7, 1, 3, "b", "abc", true},
		{7, 1, 3, "b", "", false},
		{8, 1, 2, "e", "", false},
		{8, 0, 3, "q", "", false},
		{8, 0, 2, "d", "", false},
		{8, 1, 2, "e", "de", true},
		{9, 0, 2, "f", "", false},
		{9, 1, 2, "g", "fg", true},
	}
	for i, step := range steps {
		got, complete := feedForPayload(d, testFragment(step.packetID, step.fragmentID, step.fragmentTotal, []byte(step.data)))
		if complete != step.complete || got != step.want {
			t.Fatalf("step %d (packet %d fragment %d/%d): feed() = (%q, %v), want (%q, %v)",
				i, step.packetID, step.fragmentID, step.fragmentTotal, got, complete, step.want, step.complete)
		}
	}
}

func retainedHeap(run func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&before)
	run()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc <= before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

const defraggerRetentionLimit = 128 << 10

func TestDefraggerLetsGoOfAPacketOnceItIsWhole(t *testing.T) {
	const packets = 20000
	d := newUDPDefragger()
	retained := retainedHeap(func() {
		for i := 0; i < packets; i++ {
			packetID := uint16(i + 1)
			if _, complete := feedForPayload(d, testFragment(packetID, 0, 2, bytes.Repeat([]byte{'a'}, 1100))); complete {
				t.Fatalf("packet %d completed on its first fragment", packetID)
			}
			if _, complete := feedForPayload(d, testFragment(packetID, 1, 2, bytes.Repeat([]byte{'b'}, 200))); !complete {
				t.Fatalf("packet %d did not complete on its last fragment", packetID)
			}
		}
	})
	runtime.KeepAlive(d)
	if retained > defraggerRetentionLimit {
		t.Fatalf("%d reassembled packets left %d bytes in the defragger, want at most %d", packets, retained, defraggerRetentionLimit)
	}
}

func TestDefraggerHoldsOnePacketInFlight(t *testing.T) {
	const packets = 20000
	d := newUDPDefragger()
	retained := retainedHeap(func() {
		for i := 0; i < packets; i++ {
			if _, complete := feedForPayload(d, testFragment(uint16(i+1), 0, 2, bytes.Repeat([]byte{'a'}, 1200))); complete {
				t.Fatalf("packet %d completed on its first fragment", i+1)
			}
		}
	})
	runtime.KeepAlive(d)
	if retained > defraggerRetentionLimit {
		t.Fatalf("%d incomplete packets left %d bytes in the defragger, want at most %d", packets, retained, defraggerRetentionLimit)
	}
	if got, complete := feedForPayload(d, testFragment(uint16(packets), 1, 2, []byte("tail"))); !complete || got != string(bytes.Repeat([]byte{'a'}, 1200))+"tail" {
		t.Fatalf("the packet in flight did not complete: (%d bytes, %v)", len(got), complete)
	}
}
