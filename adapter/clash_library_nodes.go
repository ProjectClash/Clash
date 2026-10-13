package adapter

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/queue"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)


type LibraryNodes struct {
	store   *outbound.NodeStore
	library *outbound.NodeLibrary
	slots   []libraryNode

	mu      sync.Mutex
	live    map[int32]*libraryLive
	sweepAt int

	urlsMu sync.Mutex
	urls   atomic.Pointer[libraryURLRecords]
	asked  atomic.Pointer[[]string]
}

type libraryURLRecords map[string]*urlRecordSet

const urlRecordChunk = 1024

type urlRecordSet struct {
	chunks []atomic.Pointer[[urlRecordChunk]atomic.Uint64]
	stored atomic.Int64
}

const libraryURLLimit = 32

func newURLRecordSet(nodes int) *urlRecordSet {
	return &urlRecordSet{chunks: make([]atomic.Pointer[[urlRecordChunk]atomic.Uint64], (nodes+urlRecordChunk-1)/urlRecordChunk)}
}

func (r *urlRecordSet) load(i int) uint64 {
	if chunk := r.chunks[i/urlRecordChunk].Load(); chunk != nil {
		return chunk[i%urlRecordChunk].Load()
	}
	return 0
}

func (r *urlRecordSet) store(i int, packed uint64) {
	r.stored.Store(time.Now().UnixNano())
	slot := &r.chunks[i/urlRecordChunk]
	chunk := slot.Load()
	if chunk == nil {
		fresh := new([urlRecordChunk]atomic.Uint64)
		if slot.CompareAndSwap(nil, fresh) {
			chunk = fresh
		} else {
			chunk = slot.Load()
		}
	}
	chunk[i%urlRecordChunk].Store(packed)
}

func (r *urlRecordSet) madeChunks() int {
	made := 0
	for i := range r.chunks {
		if r.chunks[i].Load() != nil {
			made++
		}
	}
	return made
}

type libraryLive struct {
	proxy *Proxy
	holds int
}

const libraryLiveFloor = 128

type libraryNode struct {
	nodes  *LibraryNodes
	record atomic.Uint64
}

const (
	recordAlive      = 1 << 16
	recordMade       = 1 << 17
	recordAskedShift = 18
	recordAskedMask  = 0xf
	recordTimeShift  = 22
)

const recordAskedOther = recordAskedMask

func packRecord(record C.DelayHistory, alive bool, asked uint64) uint64 {
	packed := uint64(record.Delay) | recordMade | asked<<recordAskedShift | uint64(record.Time.UnixMilli())<<recordTimeShift
	if alive {
		packed |= recordAlive
	}
	return packed
}

func (l *LibraryNodes) askedIndex(asked string) uint64 {
	if list := l.asked.Load(); list != nil {
		for i, known := range *list {
			if known == asked {
				return uint64(i)
			}
		}
	}
	l.urlsMu.Lock()
	defer l.urlsMu.Unlock()
	var next []string
	if list := l.asked.Load(); list != nil {
		for i, known := range *list {
			if known == asked {
				return uint64(i)
			}
		}
		next = append(next, *list...)
	}
	if len(next) >= recordAskedOther {
		return recordAskedOther
	}
	next = append(next, asked)
	l.asked.Store(&next)
	return uint64(len(next) - 1)
}

func unpackRecord(packed uint64) (record C.DelayHistory, alive bool, made bool) {
	if packed&recordMade == 0 {
		return C.DelayHistory{}, false, false
	}
	return C.DelayHistory{Time: time.UnixMilli(int64(packed >> recordTimeShift)), Delay: uint16(packed)},
		packed&recordAlive != 0, true
}

func NewLibraryNodes(library *outbound.NodeLibrary, options ...ProxyOption) *LibraryNodes {
	opt := applyProxyOptions(options...)
	nodes := &LibraryNodes{
		store:   outbound.NewLibraryNodeStore(library, opt.DialerForAPI, opt.TunnelForAPI, buildCatalogNode),
		library: library,
		slots:   make([]libraryNode, library.Len()),
		live:    map[int32]*libraryLive{},
		sweepAt: libraryLiveFloor,
	}
	for i := range nodes.slots {
		nodes.slots[i].nodes = nodes
	}
	return nodes
}

func (l *LibraryNodes) Len() int { return len(l.slots) }

func (l *LibraryNodes) Group(name string) ([]uint32, bool) { return l.library.Group(name) }

func (l *LibraryNodes) At(i int) C.Proxy { return &l.slots[i] }

func (l *LibraryNodes) Lookup(name string) (C.Proxy, bool) {
	i, ok := l.library.Lookup(name)
	if !ok {
		return nil, false
	}
	return &l.slots[i], true
}

func (l *LibraryNodes) Sorted() C.ProxyList { return librarySorted{l} }

type librarySorted struct{ nodes *LibraryNodes }

func (s librarySorted) Len() int         { return len(s.nodes.slots) }
func (s librarySorted) At(k int) C.Proxy { return &s.nodes.slots[s.nodes.library.SortedAt(k)] }

func (l *LibraryNodes) Rank(name string) int { return l.library.Rank(name) }

func (l *LibraryNodes) Proxies() []C.Proxy {
	proxies := make([]C.Proxy, len(l.slots))
	for i := range l.slots {
		proxies[i] = &l.slots[i]
	}
	return proxies
}

func IsLibraryNode(proxy C.Proxy) bool {
	_, ok := proxy.(*libraryNode)
	return ok
}

func (l *LibraryNodes) acquire(i int) (*Proxy, func()) {
	l.mu.Lock()
	e := l.live[int32(i)]
	if e == nil {
		if len(l.live) >= l.sweepAt {
			l.sweepLocked()
		}
		proxy := NewProxy(outbound.NewAutoCloseProxyAdapter(outbound.LibraryCatalogNode(l.store, i)))
		proxy.clashRecorded = l.slots[i].recorded
		e = &libraryLive{proxy: proxy}
		l.live[int32(i)] = e
	}
	e.holds++
	l.mu.Unlock()
	return e.proxy, func() {
		l.mu.Lock()
		e.holds--
		l.mu.Unlock()
	}
}

func (l *LibraryNodes) liveProxy(i int) *Proxy {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.live[int32(i)]; e != nil {
		return e.proxy
	}
	return nil
}

func (l *LibraryNodes) sweepLocked() {
	for i, e := range l.live {
		if e.holds == 0 && outbound.CatalogNodeHoldsNothing(e.proxy.ProxyAdapter) {
			delete(l.live, i)
		}
	}
	l.sweepAt = 2 * len(l.live)
	if l.sweepAt < libraryLiveFloor {
		l.sweepAt = libraryLiveFloor
	}
}

func (l *LibraryNodes) LiveCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.live)
}

func (l *LibraryNodes) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked()
}

func (l *LibraryNodes) RangeLive(f func(C.Proxy) bool) {
	l.mu.Lock()
	proxies := make([]C.Proxy, 0, len(l.live))
	for _, e := range l.live {
		proxies = append(proxies, e.proxy)
	}
	l.mu.Unlock()
	for _, proxy := range proxies {
		if !f(proxy) {
			return
		}
	}
}

func (l *LibraryNodes) urlRecords(url string, made bool) *urlRecordSet {
	if urls := l.urls.Load(); urls != nil {
		if records, ok := (*urls)[url]; ok || !made {
			return records
		}
	} else if !made {
		return nil
	}
	l.urlsMu.Lock()
	defer l.urlsMu.Unlock()
	old := l.urls.Load()
	if old != nil {
		if records, ok := (*old)[url]; ok {
			return records
		}
	}
	next := make(libraryURLRecords, 1)
	if old != nil {
		for u, records := range *old {
			next[u] = records
		}
	}
	for len(next) >= libraryURLLimit {
		eldest, at := "", int64(0)
		for u, records := range next {
			if stored := records.stored.Load(); eldest == "" || stored < at {
				eldest, at = u, stored
			}
		}
		delete(next, eldest)
	}
	records := newURLRecordSet(len(l.slots))
	records.stored.Store(time.Now().UnixNano())
	next[url] = records
	l.urls.Store(&next)
	return records
}

func (l *LibraryNodes) rangeURLRecords(f func(url string, records *urlRecordSet)) {
	urls := l.urls.Load()
	if urls == nil {
		return
	}
	names := make([]string, 0, len(*urls))
	for url := range *urls {
		names = append(names, url)
	}
	slices.Sort(names)
	for _, url := range names {
		f(url, (*urls)[url])
	}
}

func (n *libraryNode) index() int {
	return int((uintptr(unsafe.Pointer(n)) - uintptr(unsafe.Pointer(&n.nodes.slots[0]))) / unsafe.Sizeof(libraryNode{}))
}

func (n *libraryNode) recorded(url string, record C.DelayHistory, alive bool, urlRecord C.DelayHistory, urlAlive bool, asked string) {
	index := n.nodes.askedIndex(asked)
	n.record.Store(packRecord(record, alive, index))
	n.nodes.urlRecords(url, true).store(n.index(), packRecord(urlRecord, urlAlive, index))
}

func (n *libraryNode) LastURLTestRecord(url string) (record C.DelayHistory, alive bool, expected string, ok bool) {
	records := n.nodes.urlRecords(url, false)
	if records == nil {
		return C.DelayHistory{}, false, "", false
	}
	packed := records.load(n.index())
	record, alive, ok = unpackRecord(packed)
	if !ok {
		return C.DelayHistory{}, false, "", false
	}
	asked := (packed >> recordAskedShift) & recordAskedMask
	if list := n.nodes.asked.Load(); list != nil && asked < uint64(len(*list)) {
		expected = (*list)[asked]
	} else {
		expected = "\x00"
	}
	return record, alive, expected, true
}

func (n *libraryNode) Name() string        { return n.nodes.library.Name(n.index()) }
func (n *libraryNode) Type() C.AdapterType { return n.nodes.library.Type(n.index()) }
func (n *libraryNode) Addr() string        { return outbound.LibraryNodeAddr(n.nodes.store, n.index()) }
func (n *libraryNode) ProxyInfo() C.ProxyInfo {
	return outbound.LibraryNodeProxyInfo(n.nodes.store, n.index())
}

func (n *libraryNode) SupportUDP() bool {
	udp, _, _ := outbound.LibraryNodeAnswers(n.nodes.store, n.index())
	return udp
}

func (n *libraryNode) SupportUOT() bool {
	_, uot, _ := outbound.LibraryNodeAnswers(n.nodes.store, n.index())
	return uot
}

func (n *libraryNode) IsL3Protocol(*C.Metadata) bool {
	_, _, l3 := outbound.LibraryNodeAnswers(n.nodes.store, n.index())
	return l3
}

func (n *libraryNode) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func (n *libraryNode) Adapter() C.ProxyAdapter { return n }

func (n *libraryNode) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	proxy, release := n.nodes.acquire(n.index())
	defer release()
	return proxy.DialContext(ctx, metadata)
}

func (n *libraryNode) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy, release := n.nodes.acquire(n.index())
	defer release()
	return proxy.ListenPacketContext(ctx, metadata)
}

func (n *libraryNode) DialOptions() []dialer.Option {
	proxy, release := n.nodes.acquire(n.index())
	defer release()
	if holder, ok := proxy.ProxyAdapter.(interface{ DialOptions() []dialer.Option }); ok {
		return holder.DialOptions()
	}
	return nil
}

func (n *libraryNode) Close() error {
	if proxy := n.nodes.liveProxy(n.index()); proxy != nil {
		return proxy.Close()
	}
	return nil
}

func (n *libraryNode) Live() C.Proxy {
	if proxy := n.nodes.liveProxy(n.index()); proxy != nil {
		return proxy
	}
	return nil
}

func (n *libraryNode) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	proxy, release := n.nodes.acquire(n.index())
	defer release()
	return proxy.URLTest(ctx, url, expectedStatus)
}

func (n *libraryNode) URLTestOutcome(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (URLTestOutcome, error) {
	proxy, release := n.nodes.acquire(n.index())
	defer release()
	return proxy.URLTestOutcome(ctx, url, expectedStatus)
}

func (n *libraryNode) urlRecord(url string) (C.DelayHistory, bool, bool) {
	records := n.nodes.urlRecords(url, false)
	if records == nil {
		return C.DelayHistory{}, false, false
	}
	return unpackRecord(records.load(n.index()))
}

func (n *libraryNode) AliveForTestUrl(url string) bool {
	if _, alive, made := n.urlRecord(url); made {
		return alive
	}
	_, alive, made := unpackRecord(n.record.Load())
	return alive || !made
}

func (n *libraryNode) LastDelayForTestUrl(url string) uint16 {
	record, alive, made := n.urlRecord(url)
	if !made || !alive || record.Delay == 0 {
		return 0xffff
	}
	return record.Delay
}

func (n *libraryNode) DelayHistory() []C.DelayHistory {
	if record, _, made := unpackRecord(n.record.Load()); made {
		return []C.DelayHistory{record}
	}
	return []C.DelayHistory{}
}

func (n *libraryNode) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	if record, _, made := n.urlRecord(url); made {
		return []C.DelayHistory{record}
	}
	return []C.DelayHistory{}
}

func (n *libraryNode) ExtraDelayHistories() map[string]C.ProxyState {
	histories := map[string]C.ProxyState{}
	i := n.index()
	n.nodes.rangeURLRecords(func(url string, records *urlRecordSet) {
		if record, alive, made := unpackRecord(records.load(i)); made {
			histories[url] = C.ProxyState{Alive: alive, History: []C.DelayHistory{record}}
		}
	})
	return histories
}

func (n *libraryNode) LastDelay() (C.DelayHistory, bool) {
	record, _, made := unpackRecord(n.record.Load())
	return record, made
}

func (n *libraryNode) AppendURLDelays(dst []URLDelay) []URLDelay {
	i := n.index()
	n.nodes.rangeURLRecords(func(url string, records *urlRecordSet) {
		if record, alive, made := unpackRecord(records.load(i)); made {
			dst = append(dst, URLDelay{URL: url, Alive: alive, Recorded: true, Record: record})
		}
	})
	return dst
}

func (n *libraryNode) MarshalJSON() ([]byte, error) {
	return n.view().MarshalJSON()
}

func (n *libraryNode) view() *Proxy {
	i := n.index()
	view := NewProxy(outbound.LibraryNodeView(n.nodes.store, i))
	if record, alive, made := unpackRecord(n.record.Load()); made {
		view.alive.Store(alive)
		view.history.Put(record)
	}
	n.nodes.rangeURLRecords(func(url string, records *urlRecordSet) {
		record, alive, made := unpackRecord(records.load(i))
		if !made {
			return
		}
		state, _ := view.extra.LoadOrStoreFn(url, func() *internalProxyState {
			return &internalProxyState{history: queue.New[C.DelayHistory](1)}
		})
		state.alive.Store(alive)
		state.history.Put(record)
	})
	return view
}

type DelayRecords interface {
	LastDelay() (C.DelayHistory, bool)
	AppendURLDelays(dst []URLDelay) []URLDelay
}

var (
	_ C.Proxy                = (*libraryNode)(nil)
	_ URLTestOutcomeProvider = (*libraryNode)(nil)
	_ DelayRecords           = (*libraryNode)(nil)
	_ DelayRecords           = (*Proxy)(nil)
)

func HeldProxy(proxy C.Proxy) C.Proxy {
	if node, ok := proxy.(*libraryNode); ok {
		return node.Live()
	}
	return proxy
}

func PinnedProxy(proxy C.Proxy) C.Proxy {
	node, ok := proxy.(*libraryNode)
	if !ok {
		return proxy
	}
	live, release := node.nodes.acquire(node.index())
	release()
	return live
}
