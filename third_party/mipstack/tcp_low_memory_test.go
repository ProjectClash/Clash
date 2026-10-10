//go:build with_low_memory

package mipstack

import (
	"bytes"
	"testing"
)

func TestLowMemorySmallWritesRetainReusableBacking(t *testing.T) {
	var b tcpSendBuffer
	payload := bytes.Repeat([]byte{0x57}, 1200)
	for i := 0; i < 3; i++ {
		b.append(payload)
		b.acknowledge(len(payload))
	}
	if n := cap(b.spare); n > 1200 {
		t.Fatalf("small idle send backing=%d, want <=1200", n)
	}
	if len(b.spare) == 0 && cap(b.spare) == 0 {
		t.Fatal("small reusable backing was discarded")
	}
	p := &b.spare[:cap(b.spare)][0]
	b.append(payload)
	if &b.chunks[0].storage[0] != p {
		t.Fatal("small repeated write lost reuse")
	}
	var view tcpPayloadView
	b.view(0, len(payload), &view)
	got := make([]byte, len(payload))
	view.copyTo(got)
	if !bytes.Equal(got, payload) {
		t.Fatal("reused storage corrupted payload")
	}
}

func TestLowMemoryCapsIdleSendBacking(t *testing.T) {
	for _, size := range []int{16 << 10, 32 << 10} {
		var b tcpSendBuffer
		payload := bytes.Repeat([]byte{0x6b}, size)
		for i := 0; i < 3; i++ {
			b.append(payload)
			b.acknowledge(size)
		}
		if n := cap(b.spare); n > 16<<10 {
			t.Fatalf("%d-byte bursts retained %d bytes; low-memory maximum is 16 KiB", size, n)
		}
		if size == 16<<10 && cap(b.spare) != size {
			t.Fatal("common send chunk reuse was lost")
		}
	}
}

func TestLowMemoryCapsDrainedReadMetadata(t *testing.T) {
	b := tcpReadBuffer{chunks: make([][]byte, 0, 48)}
	for i := 0; i < 48; i++ {
		b.append([]byte{byte(i)})
	}
	got := make([]byte, 48)
	if b.read(got, len(got), nil) != len(got) {
		t.Fatal("short read")
	}
	for i, v := range got {
		if v != byte(i) {
			t.Fatal("read data changed")
		}
	}
	if n := cap(b.chunks); n > 32 {
		t.Fatalf("drained metadata slots=%d, want <=32", n)
	}
	for i := 0; i < 8; i++ {
		b.append([]byte{1})
	}
	b.read(got, 8, nil)
	if cap(b.chunks) == 0 {
		t.Fatal("common read metadata reuse was lost")
	}
}

func TestLowMemoryGrowingSmallWriteAvoidsLargeTail(t *testing.T) {
	var b tcpSendBuffer
	b.append([]byte{1})
	b.acknowledge(1)
	payload := bytes.Repeat([]byte{0x43}, 1200)
	b.append(payload)
	if len(b.chunks) != 1 {
		t.Fatalf("small write used %d chunks after a tiny write; want one fitted allocation", len(b.chunks))
	}
	if n := cap(b.chunks[0].storage); n > 1200 {
		t.Fatalf("small write retained %d bytes of backing", n)
	}
	var view tcpPayloadView
	b.view(0, len(payload), &view)
	got := make([]byte, len(payload))
	view.copyTo(got)
	if !bytes.Equal(got, payload) {
		t.Fatal("fitted write lost data")
	}
}
