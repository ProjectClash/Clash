package raw

type rawPacketElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (rawPacketElementMapper) linkerFor(elem *rawPacket) *rawPacket { return elem }

type rawPacketList struct {
	head *rawPacket
	tail *rawPacket
}

func (l *rawPacketList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
//
//go:nosplit
func (l *rawPacketList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
//
//go:nosplit
func (l *rawPacketList) Front() *rawPacket {
	return l.head
}

// Back returns the last element of list l or nil.
//
//go:nosplit
func (l *rawPacketList) Back() *rawPacket {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
//
//go:nosplit
func (l *rawPacketList) Len() (count int) {
	for e := l.Front(); e != nil; e = (rawPacketElementMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
//
//go:nosplit
func (l *rawPacketList) PushFront(e *rawPacket) {
	linker := rawPacketElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		rawPacketElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushFrontList inserts list m at the start of list l, emptying m.
//
//go:nosplit
func (l *rawPacketList) PushFrontList(m *rawPacketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		rawPacketElementMapper{}.linkerFor(l.head).SetPrev(m.tail)
		rawPacketElementMapper{}.linkerFor(m.tail).SetNext(l.head)

		l.head = m.head
	}
	m.head = nil
	m.tail = nil
}

// PushBack inserts the element e at the back of list l.
//
//go:nosplit
func (l *rawPacketList) PushBack(e *rawPacket) {
	linker := rawPacketElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		rawPacketElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
//
//go:nosplit
func (l *rawPacketList) PushBackList(m *rawPacketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		rawPacketElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		rawPacketElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
//
//go:nosplit
func (l *rawPacketList) InsertAfter(b, e *rawPacket) {
	bLinker := rawPacketElementMapper{}.linkerFor(b)
	eLinker := rawPacketElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		rawPacketElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
//
//go:nosplit
func (l *rawPacketList) InsertBefore(a, e *rawPacket) {
	aLinker := rawPacketElementMapper{}.linkerFor(a)
	eLinker := rawPacketElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		rawPacketElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
//
//go:nosplit
func (l *rawPacketList) Remove(e *rawPacket) {
	linker := rawPacketElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		rawPacketElementMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		rawPacketElementMapper{}.linkerFor(next).SetPrev(prev)
	} else if l.tail == e {
		l.tail = prev
	}

	linker.SetNext(nil)
	linker.SetPrev(nil)
}

type rawPacketEntry struct {
	next *rawPacket
	prev *rawPacket
}

// Next returns the entry that follows e in the list.
//
//go:nosplit
func (e *rawPacketEntry) Next() *rawPacket {
	return e.next
}

// Prev returns the entry that precedes e in the list.
//
//go:nosplit
func (e *rawPacketEntry) Prev() *rawPacket {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
//
//go:nosplit
func (e *rawPacketEntry) SetNext(elem *rawPacket) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
//
//go:nosplit
func (e *rawPacketEntry) SetPrev(elem *rawPacket) {
	e.prev = elem
}
