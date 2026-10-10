package fakeip

import (
	"net/netip"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/component/profile/cachefile"
	"github.com/ProjectClash/Clash/log"
)

type cachefileStore struct {
	cache *cachefile.FakeIpStore
	pending *writeBehind
}

const writeBehindDelay = 200 * time.Millisecond

type writeBehind struct {
	cache *cachefile.FakeIpStore

	flushMu sync.Mutex

	mu    sync.Mutex
	seq   uint64
	hosts map[string]pendingAddr
	ips   map[netip.Addr]pendingHost
	ops   []cachefile.FakeIPOp
	armed bool
}

type pendingAddr struct {
	ip      netip.Addr
	deleted bool
	seq     uint64
}

type pendingHost struct {
	host    string
	deleted bool
	seq     uint64
}

var (
	writeBehindsMu sync.Mutex
	writeBehinds   = map[cachefile.FakeIPStoreKey]*writeBehind{}
)

func sharedWriteBehind(cache *cachefile.FakeIpStore) *writeBehind {
	writeBehindsMu.Lock()
	defer writeBehindsMu.Unlock()
	key := cache.Key()
	if w, ok := writeBehinds[key]; ok {
		return w
	}
	w := &writeBehind{cache: cache, hosts: map[string]pendingAddr{}, ips: map[netip.Addr]pendingHost{}}
	writeBehinds[key] = w
	return w
}

// GetByHost implements store.GetByHost
func (c *cachefileStore) GetByHost(host string) (netip.Addr, bool) {
	w := c.pending
	if w == nil {
		return c.cache.GetByHost(host)
	}
	w.mu.Lock()
	if p, ok := w.hosts[host]; ok {
		w.mu.Unlock()
		return p.ip, !p.deleted
	}
	w.mu.Unlock()
	return c.cache.GetByHost(host)
}

// PutByHost implements store.PutByHost
func (c *cachefileStore) PutByHost(host string, ip netip.Addr) {
	w := c.pending
	if w == nil {
		c.cache.PutByHost(host, ip)
		return
	}
	if host == "" {
		return
	}
	w.mu.Lock()
	w.seq++
	w.hosts[host] = pendingAddr{ip: ip, seq: w.seq}
	w.ops = append(w.ops, cachefile.FakeIPOp{Kind: cachefile.FakeIPPutByHost, Host: host, IP: ip})
	w.armLocked()
	w.mu.Unlock()
}

// GetByIP implements store.GetByIP
func (c *cachefileStore) GetByIP(ip netip.Addr) (string, bool) {
	w := c.pending
	if w == nil {
		return c.cache.GetByIP(ip)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return c.getByIPLocked(ip)
}

func (c *cachefileStore) getByIPLocked(ip netip.Addr) (string, bool) {
	if p, ok := c.pending.ips[ip]; ok {
		return p.host, !p.deleted
	}
	return c.cache.GetByIP(ip)
}

// PutByIP implements store.PutByIP
func (c *cachefileStore) PutByIP(ip netip.Addr, host string) {
	w := c.pending
	if w == nil {
		c.cache.PutByIP(ip, host)
		return
	}
	w.mu.Lock()
	w.seq++
	w.ips[ip] = pendingHost{host: host, seq: w.seq}
	w.ops = append(w.ops, cachefile.FakeIPOp{Kind: cachefile.FakeIPPutByIP, Host: host, IP: ip})
	w.armLocked()
	w.mu.Unlock()
}

func (c *cachefileStore) DelByIP(ip netip.Addr) {
	w := c.pending
	if w == nil {
		c.cache.DelByIP(ip)
		return
	}
	w.mu.Lock()
	host, found := c.getByIPLocked(ip)
	w.seq++
	w.ips[ip] = pendingHost{deleted: true, seq: w.seq}
	if found && host != "" {
		w.hosts[host] = pendingAddr{deleted: true, seq: w.seq}
	}
	w.ops = append(w.ops, cachefile.FakeIPOp{Kind: cachefile.FakeIPDelByIP, IP: ip})
	w.armLocked()
	w.mu.Unlock()
}

// Exist implements store.Exist
func (c *cachefileStore) Exist(ip netip.Addr) bool {
	_, exist := c.GetByIP(ip)
	return exist
}

// CloneTo implements store.CloneTo
func (c *cachefileStore) CloneTo(store store) {}

func (c *cachefileStore) FlushFakeIP() error {
	w := c.pending
	if w == nil {
		return c.cache.FlushFakeIP()
	}
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	w.mu.Lock()
	w.ops = nil
	w.hosts = map[string]pendingAddr{}
	w.ips = map[netip.Addr]pendingHost{}
	w.mu.Unlock()
	return c.cache.FlushFakeIP()
}

func (c *cachefileStore) Sync() {
	if c.pending != nil {
		c.pending.flush()
	}
}

func (w *writeBehind) armLocked() {
	if w.armed {
		return
	}
	w.armed = true
	time.AfterFunc(writeBehindDelay, w.flush)
}

func (w *writeBehind) flush() {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	w.mu.Lock()
	ops, upto := w.ops, w.seq
	w.ops, w.armed = nil, false
	w.mu.Unlock()
	if len(ops) == 0 {
		return
	}
	if err := w.cache.Apply(ops); err != nil {
		log.Warnln("[CacheFile] write fake-ip cache to %s failed, writing one by one: %s", w.cache.DB.Path(), err.Error())
		for _, op := range ops {
			if err := w.cache.Apply([]cachefile.FakeIPOp{op}); err != nil {
				log.Warnln("[CacheFile] write fake-ip cache to %s failed: %s", w.cache.DB.Path(), err.Error())
			}
		}
	}
	w.mu.Lock()
	for host, p := range w.hosts {
		if p.seq <= upto {
			delete(w.hosts, host)
		}
	}
	for ip, p := range w.ips {
		if p.seq <= upto {
			delete(w.ips, ip)
		}
	}
	w.mu.Unlock()
}

func newCachefileStore(cache *cachefile.CacheFile, prefix netip.Prefix) *cachefileStore {
	var store *cachefile.FakeIpStore
	if prefix.Addr().Is6() {
		store = cache.FakeIpStore6()
	} else {
		store = cache.FakeIpStore()
	}
	if store.DB == nil {
		return &cachefileStore{cache: store}
	}
	return &cachefileStore{cache: store, pending: sharedWriteBehind(store)}
}
