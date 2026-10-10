// MIT License
//
// Copyright (c) 2016-2017 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package smux

import (
	"container/heap"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestShaper(t *testing.T) {
	w1 := writeRequest{seq: 1}
	w2 := writeRequest{seq: 2}
	w3 := writeRequest{seq: 3}
	w4 := writeRequest{seq: 4}
	w5 := writeRequest{seq: 5}

	var reqs shaperHeap
	heap.Push(&reqs, w5)
	heap.Push(&reqs, w4)
	heap.Push(&reqs, w3)
	heap.Push(&reqs, w2)
	heap.Push(&reqs, w1)

	for len(reqs) > 0 {
		w := heap.Pop(&reqs).(writeRequest)
		t.Log("sid:", w.frame.sid, "seq:", w.seq)
	}
}

func TestShaper2(t *testing.T) {
	w1 := writeRequest{class: CLSDATA, seq: 1}
	w2 := writeRequest{class: CLSDATA, seq: 2}
	w3 := writeRequest{class: CLSDATA, seq: 3}
	w4 := writeRequest{class: CLSDATA, seq: 4}
	w5 := writeRequest{class: CLSDATA, seq: 5}
	w6 := writeRequest{class: CLSCTRL, seq: 6, frame: Frame{sid: 10}}
	w7 := writeRequest{class: CLSCTRL, seq: 7, frame: Frame{sid: 11}}

	var reqs shaperHeap
	heap.Push(&reqs, w6)
	heap.Push(&reqs, w5)
	heap.Push(&reqs, w4)
	heap.Push(&reqs, w3)
	heap.Push(&reqs, w2)
	heap.Push(&reqs, w1)
	heap.Push(&reqs, w7)

	for len(reqs) > 0 {
		w := heap.Pop(&reqs).(writeRequest)
		t.Log("sid:", w.frame.sid, "seq:", w.seq)
	}
}

func TestShaperQueueFairness(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	sq := NewShaperQueue()

	const streams = 10
	const testDuration = 10 * time.Second

	var wg sync.WaitGroup
	sendCount := make([]uint64, streams)
	var sendCountLock sync.Mutex

	stop := make(chan struct{})

	for sid := 0; sid < streams; sid++ {
		sid := sid
		wg.Add(1)
		go func() {
			defer wg.Done()
			seq := uint32(0)
			for {
				select {
				case <-stop:
					return
				default:
				}
				sq.Push(writeRequest{
					frame: Frame{sid: uint32(sid)},
					seq:   seq,
				})
				seq++
				time.Sleep(time.Duration(rand.Intn(300)) * time.Microsecond)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				req, ok := sq.Pop()
				if !ok {
					continue
				}

				sendCountLock.Lock()
				sendCount[req.frame.sid]++
				sendCountLock.Unlock()
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sendCountLock.Lock()
				fmt.Printf("[DEBUG] Current counts: %v\n", sendCount)
				sendCountLock.Unlock()
			}
		}
	}()

	time.Sleep(testDuration)
	close(stop)
	wg.Wait()

	fmt.Println("=== FINAL COUNTS ===")
	fmt.Println(sendCount)

	total := uint64(0)
	sendCountLock.Lock()
	defer sendCountLock.Unlock()
	for _, c := range sendCount {
		total += c
	}
	avg := total / streams
	tolerance := avg / 4

	for sid, c := range sendCount {
		if c < avg-tolerance || c > avg+tolerance {
			t.Errorf("stream %d unfair: got %d, avg %d", sid, c, avg)
		}
	}
}

func TestShaperQueue_FastWriteSlowRead(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	const (
		streams      = 10
		duration     = 10 * time.Second
		producerWait = 1 * time.Microsecond
		consumerWait = 15 * time.Millisecond
	)

	sq := NewShaperQueue()

	sendCount := make([]uint64, streams)
	var sendCountLock sync.Mutex
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for sid := 0; sid < streams; sid++ {
		sid := sid
		wg.Add(1)
		go func() {
			defer wg.Done()
			seq := uint32(0)
			for {
				select {
				case <-stop:
					return
				default:
				}

				sq.Push(writeRequest{
					frame: Frame{sid: uint32(sid)},
					seq:   seq,
				})
				seq++
				time.Sleep(producerWait)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}

			req, ok := sq.Pop()
			if ok {
				sendCountLock.Lock()
				sendCount[req.frame.sid]++
				sendCountLock.Unlock()
			}

			time.Sleep(consumerWait)
		}
	}()

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sendCountLock.Lock()
				fmt.Printf("[DEBUG] Queue size=%d, counts=%v\n", sq.Len(), sendCount)
				sendCountLock.Unlock()
			}
		}
	}()

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	sendCountLock.Lock()
	defer sendCountLock.Unlock()
	fmt.Printf("=== FINAL ===\ncounts=%v\nqueue remaining=%d\n", sendCount, sq.Len())

	total := uint64(0)
	for _, v := range sendCount {
		total += v
	}
	avg := total / streams
	tolerance := avg / 3

	for sid, c := range sendCount {
		if c < avg-tolerance || c > avg+tolerance {
			t.Errorf("stream %d unfair: got %d, avg %d", sid, c, avg)
		}
	}
}

func TestShaperQueue_PopBoundary(t *testing.T) {
	sq := NewShaperQueue()

	if _, ok := sq.Pop(); ok {
		t.Fatal("Pop on empty queue should return false")
	}

	sq.Push(writeRequest{frame: Frame{sid: 10}, seq: 1})
	sq.Push(writeRequest{frame: Frame{sid: 10}, seq: 2})

	if sq.Len() != 2 {
		t.Fatalf("Expected len 2, got %d", sq.Len())
	}

	req, ok := sq.Pop()
	if !ok || req.frame.sid != 10 || req.seq != 1 {
		t.Fatalf("Expected sid 10 seq 1, got %v %v", req.frame.sid, req.seq)
	}
	if len(sq.streams) != 1 {
		t.Errorf("Expected 1 stream in map, got %d", len(sq.streams))
	}
	if sq.rrList.Len() != 1 {
		t.Errorf("Expected 1 item in rrList, got %d", sq.rrList.Len())
	}

	req, ok = sq.Pop()
	if !ok || req.frame.sid != 10 || req.seq != 2 {
		t.Fatalf("Expected sid 10 seq 2, got %v %v", req.frame.sid, req.seq)
	}
	if len(sq.streams) != 0 {
		t.Errorf("Expected 0 streams in map, got %d", len(sq.streams))
	}
	if sq.rrList.Len() != 0 {
		t.Errorf("Expected 0 items in rrList, got %d", sq.rrList.Len())
	}
	if sq.next != nil {
		t.Errorf("Expected next to be nil, got %v", sq.next)
	}

	if _, ok := sq.Pop(); ok {
		t.Fatal("Pop on empty queue should return false")
	}
}

func TestShaperQueue_MultiStreamRemoval(t *testing.T) {
	sq := NewShaperQueue()


	sq.Push(writeRequest{frame: Frame{sid: 10}, seq: 1})
	sq.Push(writeRequest{frame: Frame{sid: 20}, seq: 1})
	sq.Push(writeRequest{frame: Frame{sid: 20}, seq: 2})
	sq.Push(writeRequest{frame: Frame{sid: 30}, seq: 1})


	req, ok := sq.Pop()
	if !ok || req.frame.sid != 10 {
		t.Fatalf("Expected sid 10, got %v", req.frame.sid)
	}
	if _, exists := sq.streams[10]; exists {
		t.Error("Stream 10 should be removed")
	}
	if sq.rrList.Len() != 2 {
		t.Errorf("Expected list len 2, got %d", sq.rrList.Len())
	}

	req, ok = sq.Pop()
	if !ok || req.frame.sid != 20 || req.seq != 1 {
		t.Fatalf("Expected sid 20 seq 1, got %v %v", req.frame.sid, req.seq)
	}
	if sq.rrList.Len() != 2 {
		t.Errorf("Expected list len 2, got %d", sq.rrList.Len())
	}

	req, ok = sq.Pop()
	if !ok || req.frame.sid != 30 {
		t.Fatalf("Expected sid 30, got %v", req.frame.sid)
	}
	if _, exists := sq.streams[30]; exists {
		t.Error("Stream 30 should be removed")
	}
	if sq.rrList.Len() != 1 {
		t.Errorf("Expected list len 1, got %d", sq.rrList.Len())
	}

	req, ok = sq.Pop()
	if !ok || req.frame.sid != 20 || req.seq != 2 {
		t.Fatalf("Expected sid 20 seq 2, got %v %v", req.frame.sid, req.seq)
	}
	if sq.rrList.Len() != 0 {
		t.Errorf("Expected list len 0, got %d", sq.rrList.Len())
	}
	if sq.next != nil {
		t.Error("Expected next to be nil")
	}
}

func TestShaperHeap_MemoryLeak(t *testing.T) {
	h := &shaperHeap{}
	heap.Init(h)


	req := writeRequest{frame: Frame{sid: 1, data: make([]byte, 100)}}
	heap.Push(h, req)

	if h.Len() != 1 {
		t.Fatal("Heap len should be 1")
	}

	popped := heap.Pop(h).(writeRequest)
	if popped.frame.sid != 1 {
		t.Fatal("Incorrect popped item")
	}

	if h.Len() != 0 {
		t.Fatal("Heap len should be 0")
	}
}

func TestShaperIsEmpty(t *testing.T) {
	sq := NewShaperQueue()
	if !sq.IsEmpty() {
		t.Fatal("ShaperQueue should be empty")
	}
	sq.Push(writeRequest{
frame: newFrame(1, cmdPSH, 1),
})
	if sq.IsEmpty() {
		t.Fatal("ShaperQueue should not be empty")
	}
}
