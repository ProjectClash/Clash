// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"reflect"
	"testing"
)

func TestPrioritySchedulerUrgency(t *testing.T) {
	const maxFrameSize = 16
	sc := &serverConn{maxFrameSize: maxFrameSize}
	ws := newPriorityWriteSchedulerRFC9218()
	streams := make([]*stream, 5)
	for i := range streams {
		streamID := uint32(i) + 1
		streams[i] = &stream{
			id: streamID,
			sc: sc,
		}
		streams[i].flow.add(1 << 20)
		ws.OpenStream(streamID, OpenStreamOptions{
			priority: PriorityParam{
				urgency:     7,
				incremental: 0,
			},
		})
		wr := FrameWriteRequest{
			write: &writeData{
				streamID:  streamID,
				p:         make([]byte, maxFrameSize*(i+1)),
				endStream: false,
			},
			stream: streams[i],
		}
		ws.Push(wr)
	}
	for i := range streams {
		streamID := uint32(i) + 1
		if streamID%2 == 1 {
			continue
		}
		ws.AdjustStream(streamID, PriorityParam{
			urgency:     0,
			incremental: 0,
		})
	}
	const controlFrames = 2
	for i := 0; i < controlFrames; i++ {
		ws.Push(makeWriteNonStreamRequest())
	}

	for i := 0; i < controlFrames; i++ {
		wr, ok := ws.Pop()
		if !ok || wr.StreamID() != 0 {
			t.Fatalf("wr.Pop() = stream %v, %v; want 0, true", wr.StreamID(), ok)
		}
	}

	want := []uint32{2, 2, 4, 4, 4, 4, 1, 3, 3, 3, 5, 5, 5, 5, 5}
	var got []uint32
	for {
		wr, ok := ws.Pop()
		if !ok {
			break
		}
		if wr.DataSize() != maxFrameSize {
			t.Fatalf("wr.Pop() = %v data bytes, want %v", wr.DataSize(), maxFrameSize)
		}
		got = append(got, wr.StreamID())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("popped streams %v, want %v", got, want)
	}
}

func TestPrioritySchedulerIncremental(t *testing.T) {
	const maxFrameSize = 16
	sc := &serverConn{maxFrameSize: maxFrameSize}
	ws := newPriorityWriteSchedulerRFC9218()
	streams := make([]*stream, 5)
	for i := range streams {
		streamID := uint32(i) + 1
		streams[i] = &stream{
			id: streamID,
			sc: sc,
		}
		streams[i].flow.add(1 << 20)
		ws.OpenStream(streamID, OpenStreamOptions{
			priority: PriorityParam{
				urgency:     7,
				incremental: 0,
			},
		})
		wr := FrameWriteRequest{
			write: &writeData{
				streamID:  streamID,
				p:         make([]byte, maxFrameSize*(i+1)),
				endStream: false,
			},
			stream: streams[i],
		}
		ws.Push(wr)
	}
	for i := range streams {
		streamID := uint32(i) + 1
		if streamID%2 == 1 {
			continue
		}
		ws.AdjustStream(streamID, PriorityParam{
			urgency:     7,
			incremental: 1,
		})
	}
	const controlFrames = 2
	for i := 0; i < controlFrames; i++ {
		ws.Push(makeWriteNonStreamRequest())
	}

	for i := 0; i < controlFrames; i++ {
		wr, ok := ws.Pop()
		if !ok || wr.StreamID() != 0 {
			t.Fatalf("wr.Pop() = stream %v, %v; want 0, true", wr.StreamID(), ok)
		}
	}

	want := []uint32{2, 1, 4, 3, 2, 3, 4, 3, 4, 5, 4, 5, 5, 5, 5}
	var got []uint32
	for {
		wr, ok := ws.Pop()
		if !ok {
			break
		}
		if wr.DataSize() != maxFrameSize {
			t.Fatalf("wr.Pop() = %v data bytes, want %v", wr.DataSize(), maxFrameSize)
		}
		got = append(got, wr.StreamID())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("popped streams %v, want %v", got, want)
	}
}

func TestPrioritySchedulerUrgencyAndIncremental(t *testing.T) {
	const maxFrameSize = 16
	sc := &serverConn{maxFrameSize: maxFrameSize}
	ws := newPriorityWriteSchedulerRFC9218()
	streams := make([]*stream, 6)
	for i := range streams {
		streamID := uint32(i) + 1
		streams[i] = &stream{
			id: streamID,
			sc: sc,
		}
		streams[i].flow.add(1 << 20)
		ws.OpenStream(streamID, OpenStreamOptions{
			priority: PriorityParam{
				urgency:     7,
				incremental: 0,
			},
		})
		wr := FrameWriteRequest{
			write: &writeData{
				streamID:  streamID,
				p:         make([]byte, maxFrameSize*(i+1)),
				endStream: false,
			},
			stream: streams[i],
		}
		ws.Push(wr)
	}
	for i := range streams {
		streamID := uint32(i) + 1
		if streamID%2 == 1 {
			continue
		}
		ws.AdjustStream(streamID, PriorityParam{
			urgency:     0,
			incremental: 1,
		})
	}
	ws.CloseStream(1)
	ws.CloseStream(4)
	const controlFrames = 2
	for i := 0; i < controlFrames; i++ {
		ws.Push(makeWriteNonStreamRequest())
	}

	for i := 0; i < controlFrames; i++ {
		wr, ok := ws.Pop()
		if !ok || wr.StreamID() != 0 {
			t.Fatalf("wr.Pop() = stream %v, %v; want 0, true", wr.StreamID(), ok)
		}
	}

	want := []uint32{2, 6, 2, 6, 6, 6, 6, 6, 3, 3, 3, 5, 5, 5, 5, 5}
	var got []uint32
	for {
		wr, ok := ws.Pop()
		if !ok {
			break
		}
		if wr.DataSize() != maxFrameSize {
			t.Fatalf("wr.Pop() = %v data bytes, want %v", wr.DataSize(), maxFrameSize)
		}
		got = append(got, wr.StreamID())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("popped streams %v, want %v", got, want)
	}
}

func TestPrioritySchedulerIdempotentUpdate(t *testing.T) {
	const maxFrameSize = 16
	sc := &serverConn{maxFrameSize: maxFrameSize}
	ws := newPriorityWriteSchedulerRFC9218()
	streams := make([]*stream, 6)
	for i := range streams {
		streamID := uint32(i) + 1
		streams[i] = &stream{
			id: streamID,
			sc: sc,
		}
		streams[i].flow.add(1 << 20)
		ws.OpenStream(streamID, OpenStreamOptions{
			priority: PriorityParam{
				urgency:     7,
				incremental: 0,
			},
		})
		wr := FrameWriteRequest{
			write: &writeData{
				streamID:  streamID,
				p:         make([]byte, maxFrameSize*(i+1)),
				endStream: false,
			},
			stream: streams[i],
		}
		ws.Push(wr)
	}
	for i := range streams {
		streamID := uint32(i) + 1
		if streamID%2 == 1 {
			continue
		}
		ws.AdjustStream(streamID, PriorityParam{
			urgency:     0,
			incremental: 1,
		})
	}
	ws.CloseStream(1)
	for i := range streams {
		streamID := uint32(i) + 1
		if streamID%2 == 1 {
			continue
		}
		ws.AdjustStream(streamID, PriorityParam{
			urgency:     0,
			incremental: 1,
		})
	}
	ws.CloseStream(2)
	const controlFrames = 2
	for i := 0; i < controlFrames; i++ {
		ws.Push(makeWriteNonStreamRequest())
	}

	for i := 0; i < controlFrames; i++ {
		wr, ok := ws.Pop()
		if !ok || wr.StreamID() != 0 {
			t.Fatalf("wr.Pop() = stream %v, %v; want 0, true", wr.StreamID(), ok)
		}
	}

	want := []uint32{4, 6, 4, 6, 4, 6, 4, 6, 6, 6, 3, 3, 3, 5, 5, 5, 5, 5}
	var got []uint32
	for {
		wr, ok := ws.Pop()
		if !ok {
			break
		}
		if wr.DataSize() != maxFrameSize {
			t.Fatalf("wr.Pop() = %v data bytes, want %v", wr.DataSize(), maxFrameSize)
		}
		got = append(got, wr.StreamID())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("popped streams %v, want %v", got, want)
	}
}
