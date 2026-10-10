package queue

import (
	"sync"
	"testing"
)

func TestLastAndPopReadTheLengthUnderTheLock(t *testing.T) {
	q := New[int](0)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			q.Put(i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = q.Last()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = q.Pop()
		}
	}()
	wg.Wait()
}
