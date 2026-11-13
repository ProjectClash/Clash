package deque

import "fmt"

const minCapacity = 16

type Deque[T any] struct {
	buf    []T
	head   int
	tail   int
	count  int
	minCap int
}

func New[T any](size ...int) *Deque[T] {
	var capacity, minimum int
	if len(size) >= 1 {
		capacity = size[0]
		if len(size) >= 2 {
			minimum = size[1]
		}
	}

	minCap := minCapacity
	for minCap < minimum {
		minCap <<= 1
	}

	var buf []T
	if capacity != 0 {
		bufSize := minCap
		for bufSize < capacity {
			bufSize <<= 1
		}
		buf = make([]T, bufSize)
	}

	return &Deque[T]{
		buf:    buf,
		minCap: minCap,
	}
}

func (q *Deque[T]) Cap() int {
	if q == nil {
		return 0
	}
	return len(q.buf)
}

func (q *Deque[T]) Len() int {
	if q == nil {
		return 0
	}
	return q.count
}

func (q *Deque[T]) PushBack(elem T) {
	q.growIfFull()

	q.buf[q.tail] = elem
	q.tail = q.next(q.tail)
	q.count++
}

func (q *Deque[T]) PushFront(elem T) {
	q.growIfFull()

	q.head = q.prev(q.head)
	q.buf[q.head] = elem
	q.count++
}

func (q *Deque[T]) PopFront() T {
	if q.count <= 0 {
		panic("deque: PopFront() called on empty queue")
	}
	ret := q.buf[q.head]
	var zero T
	q.buf[q.head] = zero
	q.head = q.next(q.head)
	q.count--

	q.shrinkIfExcess()
	return ret
}

func (q *Deque[T]) PopBack() T {
	if q.count <= 0 {
		panic("deque: PopBack() called on empty queue")
	}

	q.tail = q.prev(q.tail)

	ret := q.buf[q.tail]
	var zero T
	q.buf[q.tail] = zero
	q.count--

	q.shrinkIfExcess()
	return ret
}

func (q *Deque[T]) Front() T {
	if q.count <= 0 {
		panic("deque: Front() called when empty")
	}
	return q.buf[q.head]
}

func (q *Deque[T]) Back() T {
	if q.count <= 0 {
		panic("deque: Back() called when empty")
	}
	return q.buf[q.prev(q.tail)]
}

func (q *Deque[T]) At(i int) T {
	if i < 0 || i >= q.count {
		panic(outOfRangeText(i, q.Len()))
	}
	return q.buf[(q.head+i)&(len(q.buf)-1)]
}

func (q *Deque[T]) Set(i int, item T) {
	if i < 0 || i >= q.count {
		panic(outOfRangeText(i, q.Len()))
	}
	q.buf[(q.head+i)&(len(q.buf)-1)] = item
}

func (q *Deque[T]) Clear() {
	var zero T
	modBits := len(q.buf) - 1
	h := q.head
	for i := 0; i < q.Len(); i++ {
		q.buf[(h+i)&modBits] = zero
	}
	q.head = 0
	q.tail = 0
	q.count = 0
}

func (q *Deque[T]) Rotate(n int) {
	if q.Len() <= 1 {
		return
	}
	n %= q.count
	if n == 0 {
		return
	}

	modBits := len(q.buf) - 1
	if q.head == q.tail {
		q.head = (q.head + n) & modBits
		q.tail = q.head
		return
	}

	var zero T

	if n < 0 {
		for ; n < 0; n++ {
			q.head = (q.head - 1) & modBits
			q.tail = (q.tail - 1) & modBits
			q.buf[q.head] = q.buf[q.tail]
			q.buf[q.tail] = zero
		}
		return
	}

	for ; n > 0; n-- {
		q.buf[q.tail] = q.buf[q.head]
		q.buf[q.head] = zero
		q.head = (q.head + 1) & modBits
		q.tail = (q.tail + 1) & modBits
	}
}

func (q *Deque[T]) Index(f func(T) bool) int {
	if q.Len() > 0 {
		modBits := len(q.buf) - 1
		for i := 0; i < q.count; i++ {
			if f(q.buf[(q.head+i)&modBits]) {
				return i
			}
		}
	}
	return -1
}

func (q *Deque[T]) RIndex(f func(T) bool) int {
	if q.Len() > 0 {
		modBits := len(q.buf) - 1
		for i := q.count - 1; i >= 0; i-- {
			if f(q.buf[(q.head+i)&modBits]) {
				return i
			}
		}
	}
	return -1
}

func (q *Deque[T]) Insert(at int, item T) {
	if at < 0 || at > q.count {
		panic(outOfRangeText(at, q.Len()))
	}
	if at*2 < q.count {
		q.PushFront(item)
		front := q.head
		for i := 0; i < at; i++ {
			next := q.next(front)
			q.buf[front], q.buf[next] = q.buf[next], q.buf[front]
			front = next
		}
		return
	}
	swaps := q.count - at
	q.PushBack(item)
	back := q.prev(q.tail)
	for i := 0; i < swaps; i++ {
		prev := q.prev(back)
		q.buf[back], q.buf[prev] = q.buf[prev], q.buf[back]
		back = prev
	}
}

func (q *Deque[T]) Remove(at int) T {
	if at < 0 || at >= q.Len() {
		panic(outOfRangeText(at, q.Len()))
	}

	rm := (q.head + at) & (len(q.buf) - 1)
	if at*2 < q.count {
		for i := 0; i < at; i++ {
			prev := q.prev(rm)
			q.buf[prev], q.buf[rm] = q.buf[rm], q.buf[prev]
			rm = prev
		}
		return q.PopFront()
	}
	swaps := q.count - at - 1
	for i := 0; i < swaps; i++ {
		next := q.next(rm)
		q.buf[rm], q.buf[next] = q.buf[next], q.buf[rm]
		rm = next
	}
	return q.PopBack()
}

func (q *Deque[T]) SetMinCapacity(minCapacityExp uint) {
	if 1<<minCapacityExp > minCapacity {
		q.minCap = 1 << minCapacityExp
	} else {
		q.minCap = minCapacity
	}
}

func (q *Deque[T]) prev(i int) int {
	return (i - 1) & (len(q.buf) - 1)
}

func (q *Deque[T]) next(i int) int {
	return (i + 1) & (len(q.buf) - 1)
}

func (q *Deque[T]) growIfFull() {
	if q.count != len(q.buf) {
		return
	}
	if len(q.buf) == 0 {
		if q.minCap == 0 {
			q.minCap = minCapacity
		}
		q.buf = make([]T, q.minCap)
		return
	}
	q.resize()
}

func (q *Deque[T]) shrinkIfExcess() {
	if len(q.buf) > q.minCap && (q.count<<2) == len(q.buf) {
		q.resize()
	}
}

func (q *Deque[T]) resize() {
	newBuf := make([]T, q.count<<1)
	if q.tail > q.head {
		copy(newBuf, q.buf[q.head:q.tail])
	} else {
		n := copy(newBuf, q.buf[q.head:])
		copy(newBuf[n:], q.buf[:q.tail])
	}

	q.head = 0
	q.tail = q.count
	q.buf = newBuf
}

func outOfRangeText(i, len int) string {
	return fmt.Sprintf("deque: index out of range %d with length %d", i, len)
}
