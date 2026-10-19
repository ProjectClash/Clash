package outbound

import (
	"context"
	"encoding/hex"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"

	"github.com/gofrs/uuid/v5"
)


const nodeCatalogLimit = 64

type catalogTraits uint16

const (
	catalogUDP catalogTraits = 1 << iota
	catalogUOT
	catalogL3
	catalogResetter
	catalogReleaser
	catalogXUDP
	catalogTFO
	catalogMPTCP
	catalogSMUX
)

type catalogNode struct {
	name   string
	store  *NodeStore
	ref    uint32
	tp     uint8
	traits catalogTraits

	use sessionUse

	buildMu  sync.Mutex
	expanded atomic.Pointer[catalogExpansion]
	probe    *catalogExpansion
	prev     *catalogNode
	next     *catalogNode
}

type catalogExpansion struct {
	adapter ProxyAdapter
	key     string
	owners  int
}

func NewCatalogNode(built ProxyAdapter, config string, store *NodeStore) (ProxyAdapter, bool) {
	record, tp, traits, ok := catalogFacts(built, config, store.providerName)
	if !ok {
		return built, false
	}
	ref, err := store.add(record)
	if err != nil {
		return built, false
	}
	node := &catalogNode{name: built.Name(), store: store, ref: ref, tp: tp, traits: traits}
	_ = built.Close()
	return node, true
}

func catalogFacts(built ProxyAdapter, config string, storeProvider string) (record []byte, tp uint8, traits catalogTraits, ok bool) {
	encoded, err := built.MarshalJSON()
	if err != nil || int(built.Type()) < 0 || int(built.Type()) > 0xff {
		return nil, 0, 0, false
	}
	id, base := baseJSONID(built, encoded)
	json := ""
	if !base {
		json = string(encoded)
	}
	info := built.ProxyInfo()
	record = encodeNodeRecord(id, base, json, built.Addr(), info, storeProvider, config)
	for _, trait := range [...]struct {
		on  bool
		bit catalogTraits
	}{
		{built.SupportUDP(), catalogUDP},
		{built.SupportUOT(), catalogUOT},
		{built.IsL3Protocol(&C.Metadata{}), catalogL3},
		{info.XUDP, catalogXUDP},
		{info.TFO, catalogTFO},
		{info.MPTCP, catalogMPTCP},
		{info.SMUX, catalogSMUX},
	} {
		if trait.on {
			traits |= trait.bit
		}
	}
	if _, ok := built.(NetworkResetter); ok && keepsOwnSessions(built) {
		traits |= catalogResetter
	}
	if _, ok := built.(SessionReleaser); ok {
		traits |= catalogReleaser
	}
	return record, uint8(built.Type()), traits, true
}

func NewSingleCatalogNode(built ProxyAdapter, config string, providerName string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, build NodeBuilder) (ProxyAdapter, bool) {
	return NewCatalogNode(built, config, newSingleNodeStore(providerName, dialerForAPI, tunnelForAPI, build))
}

var catalogRecordRead func()

func (n *catalogNode) view() (nodeRecordView, bool) {
	record, heap := n.store.record(n.ref)
	if catalogRecordRead != nil {
		catalogRecordRead()
	}
	return viewNodeRecord(record), heap
}

func (n *catalogNode) Name() string                     { return n.name }
func (n *catalogNode) Type() C.AdapterType              { return C.AdapterType(n.tp) }
func (n *catalogNode) SupportUDP() bool                 { return n.traits&catalogUDP != 0 }
func (n *catalogNode) SupportUOT() bool                 { return n.traits&catalogUOT != 0 }
func (n *catalogNode) IsL3Protocol(*C.Metadata) bool    { return n.traits&catalogL3 != 0 }
func (n *catalogNode) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (n *catalogNode) keepsSessions() bool              { return n.traits&(catalogResetter|catalogReleaser) != 0 }

func (n *catalogNode) Addr() string {
	defer runtime.KeepAlive(n)
	v, heap := n.view()
	return text(v.addr, heap)
}

func (n *catalogNode) ProxyInfo() C.ProxyInfo {
	defer runtime.KeepAlive(n)
	v, heap := n.view()
	return proxyInfoOfRecord(n.store, n.traits, v, heap)
}

func proxyInfoOfRecord(store *NodeStore, traits catalogTraits, v nodeRecordView, heap bool) C.ProxyInfo {
	provider := store.providerName
	if v.ownProvider {
		provider = text(v.provider, heap)
	}
	return C.ProxyInfo{
		XUDP:         traits&catalogXUDP != 0,
		TFO:          traits&catalogTFO != 0,
		MPTCP:        traits&catalogMPTCP != 0,
		SMUX:         traits&catalogSMUX != 0,
		Interface:    text(v.iface, heap),
		RoutingMark:  v.routingMark,
		ProviderName: provider,
		DialerProxy:  text(v.dialerProxy, heap),
	}
}

func (n *catalogNode) MarshalJSON() ([]byte, error) {
	defer runtime.KeepAlive(n)
	v, _ := n.view()
	if !v.baseJSON {
		return append([]byte(nil), v.json...), nil
	}
	return appendBaseJSON(nil, v.id, n.Type()), nil
}

func appendBaseJSON(b []byte, id uuid.UUID, tp C.AdapterType) []byte {
	b = append(b, `{"id":"`...)
	b = AppendUUID(b, id)
	b = append(b, `","type":"`...)
	b = append(b, tp.String()...)
	return append(b, `"}`...)
}

func AppendUUID(b []byte, id uuid.UUID) []byte {
	var text [36]byte
	hex.Encode(text[0:8], id[0:4])
	text[8] = '-'
	hex.Encode(text[9:13], id[4:6])
	text[13] = '-'
	hex.Encode(text[14:18], id[6:8])
	text[18] = '-'
	hex.Encode(text[19:23], id[8:10])
	text[23] = '-'
	hex.Encode(text[24:36], id[10:16])
	return append(b, text[:]...)
}

func baseJSONID(built ProxyAdapter, encoded []byte) (uuid.UUID, bool) {
	holder, ok := built.(interface{ Id() string })
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.FromString(holder.Id())
	if err != nil || string(appendBaseJSON(nil, id, built.Type())) != string(encoded) {
		return uuid.Nil, false
	}
	return id, true
}

func catalogNodeOf(a C.ProxyAdapter) (*catalogNode, bool) {
	if wrapped, ok := a.(*autoCloseProxyAdapter); ok {
		a = wrapped.ProxyAdapter
	}
	node, ok := a.(*catalogNode)
	return node, ok
}

func CatalogNodeID(a C.ProxyAdapter) (id uuid.UUID, ok bool) {
	node, ok := catalogNodeOf(a)
	if !ok {
		return uuid.Nil, false
	}
	defer runtime.KeepAlive(node)
	v, _ := node.view()
	return v.id, v.baseJSON
}

func (n *catalogNode) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	adapter, err := n.acquire(dialer.DialKindOf(ctx) == dialer.DialKindProbe)
	if err != nil {
		return nil, err
	}
	return adapter.DialContext(ctx, metadata)
}

func (n *catalogNode) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	adapter, err := n.acquire(dialer.DialKindOf(ctx) == dialer.DialKindProbe)
	if err != nil {
		return nil, err
	}
	return adapter.ListenPacketContext(ctx, metadata)
}

func (n *catalogNode) DialOptions() []dialer.Option {
	adapter, err := n.acquire(false)
	if err != nil {
		return nil
	}
	return adapter.DialOptions()
}

func (n *catalogNode) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	adapter, err := n.acquire(false)
	if err != nil {
		return err
	}
	return adapter.ResolveUDP(ctx, metadata)
}

func (n *catalogNode) Close() error {
	var err error
	for _, e := range nodeCatalog.drop(n) {
		if closeErr := e.adapter.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

func (n *catalogNode) current() (ProxyAdapter, bool) {
	if e := n.expanded.Load(); e != nil {
		return e.adapter, true
	}
	return nil, false
}

func (n *catalogNode) ResetNetwork() {
	for _, adapter := range nodeCatalog.outboundsOf(n) {
		if resetter, ok := adapter.(NetworkResetter); ok {
			resetter.ResetNetwork()
		}
	}
}

func (n *catalogNode) ReleaseSessions() bool {
	e, shared := nodeCatalog.beginRelease(n)
	if shared {
		return false
	}
	if e == nil {
		return true
	}
	defer nodeCatalog.endRelease(e)
	if releaser, ok := e.adapter.(SessionReleaser); ok {
		return releaser.ReleaseSessions()
	}
	if resetter, ok := e.adapter.(NetworkResetter); ok {
		resetter.ResetNetwork()
	}
	return true
}

func (n *catalogNode) key() (key string, config string) {
	defer runtime.KeepAlive(n)
	v, heap := n.view()
	config = text(v.config, heap)
	return n.store.providerName + "\x00" + config, config
}

func (n *catalogNode) acquire(probe bool) (ProxyAdapter, error) {
	if probe && n.traits&catalogReleaser != 0 {
		probe = false
	}
	if adapter, ok := nodeCatalog.take(n, probe, ""); ok {
		return adapter, nil
	}
	n.buildMu.Lock()
	defer n.buildMu.Unlock()
	key, config := n.key()
	if adapter, ok := nodeCatalog.take(n, probe, key); ok {
		return adapter, nil
	}
	adapter, err := n.store.build(config, n.store.dialerForAPI, n.store.tunnelForAPI, n.store.providerName)
	if err != nil {
		return nil, err
	}
	adapter, evicted := nodeCatalog.place(n, probe, &catalogExpansion{adapter: adapter, key: key, owners: 1})
	closeExpansionsApart(evicted)
	return adapter, nil
}

func (n *catalogNode) afterUse() {
	if e := nodeCatalog.endProbe(n); e != nil {
		closeExpansionsApart([]*catalogExpansion{e})
	}
}

type catalogList struct {
	mu     sync.Mutex
	head   *catalogNode
	tail   *catalogNode
	count  int
	limit  int
	pinned map[*catalogNode]struct{}
	shared map[string]*catalogExpansion
}

var nodeCatalog catalogList

func (c *catalogList) limitLocked() int {
	if c.limit > 0 {
		return c.limit
	}
	return nodeCatalogLimit
}

func (c *catalogList) take(n *catalogNode, probe bool, key string) (ProxyAdapter, bool) {
	c.mu.Lock()
	var evicted []*catalogExpansion
	defer func() {
		c.mu.Unlock()
		closeExpansionsApart(evicted)
	}()
	if e := n.expanded.Load(); e != nil {
		if !probe && c.head != n {
			c.unlinkLocked(n)
			c.pushFrontLocked(n)
		}
		return e.adapter, true
	}
	if e := n.probe; e != nil {
		if !probe {
			n.probe = nil
			evicted = c.listLocked(n, e)
		}
		return e.adapter, true
	}
	if key == "" {
		return nil, false
	}
	e, ok := c.shared[key]
	if !ok {
		return nil, false
	}
	e.owners++
	evicted = c.holdLocked(n, probe, e)
	return e.adapter, true
}

func (c *catalogList) place(n *catalogNode, probe bool, built *catalogExpansion) (ProxyAdapter, []*catalogExpansion) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shared == nil {
		c.shared = map[string]*catalogExpansion{}
	}
	e := built
	var evicted []*catalogExpansion
	if existing, ok := c.shared[built.key]; ok {
		existing.owners++
		e = existing
		evicted = append(evicted, built)
	} else {
		c.shared[built.key] = built
	}
	evicted = append(evicted, c.holdLocked(n, probe, e)...)
	return e.adapter, evicted
}

func (c *catalogList) holdLocked(n *catalogNode, probe bool, e *catalogExpansion) []*catalogExpansion {
	if probe {
		n.probe = e
		return nil
	}
	return c.listLocked(n, e)
}

func (c *catalogList) listLocked(n *catalogNode, e *catalogExpansion) []*catalogExpansion {
	n.expanded.Store(e)
	c.pushFrontLocked(n)
	return c.trimLocked(n)
}

func (c *catalogList) releaseLocked(e *catalogExpansion) *catalogExpansion {
	e.owners--
	if e.owners > 0 {
		return nil
	}
	if c.shared[e.key] == e {
		delete(c.shared, e.key)
	}
	return e
}

func (c *catalogList) endProbe(n *catalogNode) *catalogExpansion {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n.probe == nil || !n.use.mu.TryLock() {
		return nil
	}
	idle := n.use.dialing == 0 && n.use.conns == 0
	n.use.mu.Unlock()
	if !idle {
		return nil
	}
	e := n.probe
	n.probe = nil
	return c.releaseLocked(e)
}

func (c *catalogList) drop(n *catalogNode) (closing []*catalogExpansion) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := n.expanded.Swap(nil); e != nil {
		c.unlinkLocked(n)
		if e = c.releaseLocked(e); e != nil {
			closing = append(closing, e)
		}
	}
	if e := n.probe; e != nil {
		n.probe = nil
		if e = c.releaseLocked(e); e != nil {
			closing = append(closing, e)
		}
	}
	delete(c.pinned, n)
	return closing
}

func (c *catalogList) outboundsOf(n *catalogNode) (adapters []ProxyAdapter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := n.expanded.Load(); e != nil {
		adapters = append(adapters, e.adapter)
	}
	if e := n.probe; e != nil {
		adapters = append(adapters, e.adapter)
	}
	return adapters
}

func (c *catalogList) beginRelease(n *catalogNode) (e *catalogExpansion, shared bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e = n.expanded.Load()
	if e == nil {
		return nil, false
	}
	if e.owners > 1 {
		return nil, true
	}
	if c.shared[e.key] == e {
		delete(c.shared, e.key)
	}
	return e, false
}

func (c *catalogList) endRelease(e *catalogExpansion) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.owners == 0 {
		return
	}
	if _, taken := c.shared[e.key]; !taken {
		c.shared[e.key] = e
	}
}

func (c *catalogList) trimLocked(keep *catalogNode) (evicted []*catalogExpansion) {
	limit := c.limitLocked()
	for node := c.tail; node != nil && c.count > limit; {
		older := node.prev
		if node != keep {
			if _, pinned := c.pinned[node]; !pinned {
				if e, ok := c.evictLocked(node); ok && e != nil {
					evicted = append(evicted, e)
				}
			}
		}
		node = older
	}
	return evicted
}

func (c *catalogList) evictLocked(n *catalogNode) (*catalogExpansion, bool) {
	if !n.use.mu.TryLock() {
		return nil, false
	}
	defer n.use.mu.Unlock()
	if n.use.dialing > 0 || n.use.conns > 0 {
		return nil, false
	}
	e := n.expanded.Swap(nil)
	if e == nil {
		return nil, false
	}
	c.unlinkLocked(n)
	if e = c.releaseLocked(e); e == nil {
		return nil, true
	}
	n.use.open, n.use.userOpened = false, false
	return e, true
}

func (c *catalogList) pushFrontLocked(n *catalogNode) {
	n.prev, n.next = nil, c.head
	if c.head != nil {
		c.head.prev = n
	}
	c.head = n
	if c.tail == nil {
		c.tail = n
	}
	c.count++
}

func (c *catalogList) unlinkLocked(n *catalogNode) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		c.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		c.tail = n.prev
	}
	n.prev, n.next = nil, nil
	c.count--
}

func closeExpansions(evicted []*catalogExpansion) {
	for _, e := range evicted {
		if releaser, ok := e.adapter.(SessionReleaser); ok {
			_ = releaser.ReleaseSessions()
		}
		_ = e.adapter.Close()
	}
}

func closeExpansionsApart(evicted []*catalogExpansion) {
	if len(evicted) > 0 {
		go closeExpansions(evicted)
	}
}

func TrimNodeCatalog() int {
	nodeCatalog.mu.Lock()
	before := nodeCatalog.count
	evicted := nodeCatalog.trimLocked(nil)
	left := before - nodeCatalog.count
	nodeCatalog.mu.Unlock()
	closeExpansions(evicted)
	return left
}

func SetNodeCatalogPins(proxies []C.ProxyAdapter) {
	pinned := make(map[*catalogNode]struct{}, len(proxies))
	for _, proxy := range proxies {
		if node, ok := catalogNodeOf(proxy); ok {
			pinned[node] = struct{}{}
		}
	}
	nodeCatalog.mu.Lock()
	nodeCatalog.pinned = pinned
	nodeCatalog.mu.Unlock()
}

func NodeCatalogBuilt() int {
	nodeCatalog.mu.Lock()
	defer nodeCatalog.mu.Unlock()
	return nodeCatalog.count
}

func NodeCatalogOutbounds() int {
	nodeCatalog.mu.Lock()
	defer nodeCatalog.mu.Unlock()
	return len(nodeCatalog.shared)
}

func SetNodeCatalogLimit(limit int) (restore func()) {
	nodeCatalog.mu.Lock()
	previous := nodeCatalog.limit
	nodeCatalog.limit = limit
	nodeCatalog.mu.Unlock()
	return func() {
		nodeCatalog.mu.Lock()
		nodeCatalog.limit = previous
		nodeCatalog.mu.Unlock()
	}
}

func IsCatalogNode(a C.ProxyAdapter) (catalog bool, built bool) {
	node, ok := catalogNodeOf(a)
	if !ok {
		return false, false
	}
	_, built = node.current()
	return true, built
}

func NodeCatalogLimit() int {
	nodeCatalog.mu.Lock()
	defer nodeCatalog.mu.Unlock()
	return nodeCatalog.limitLocked()
}

func IsCatalogNodePinned(a C.ProxyAdapter) bool {
	node, ok := catalogNodeOf(a)
	if !ok {
		return false
	}
	nodeCatalog.mu.Lock()
	defer nodeCatalog.mu.Unlock()
	_, pinned := nodeCatalog.pinned[node]
	return pinned
}

func CatalogNodeConfig(a C.ProxyAdapter) (string, bool) {
	node, ok := catalogNodeOf(a)
	if !ok {
		return "", false
	}
	_, config := node.key()
	return config, true
}

func LibraryNodeConfig(store *NodeStore, i int) string {
	_, config := libraryNodeAt(store, i).key()
	return config
}
