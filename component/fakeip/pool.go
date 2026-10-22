package fakeip

import (
	"errors"
	"net/netip"
	"strings"
	"sync"

	"github.com/ProjectClash/Clash/component/profile/cachefile"
	"github.com/ProjectClash/Clash/log"

	"go4.org/netipx"
)

const (
	offsetKey = "key-offset-fake-ip"
	cycleKey  = "key-cycle-fake-ip"
)

type store interface {
	GetByHost(host string) (netip.Addr, bool)
	PutByHost(host string, ip netip.Addr)
	GetByIP(ip netip.Addr) (string, bool)
	PutByIP(ip netip.Addr, host string)
	DelByIP(ip netip.Addr)
	Exist(ip netip.Addr) bool
	CloneTo(store)
	FlushFakeIP() error
}

// Pool is an implementation about fake ip generator without storage
type Pool struct {
	gateway netip.Addr
	first   netip.Addr
	last    netip.Addr
	ipnet   netip.Prefix
	*allocator
}

type allocator struct {
	offset netip.Addr
	cycle  bool
	mux    sync.Mutex
	store  store
	flushPending bool
	retired bool
}

// Lookup return a fake ip with host
func (p *Pool) Lookup(host string) netip.Addr {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.settleLocked()

	// RFC4343: DNS Case Insensitive, we SHOULD return result with all cases.
	host = strings.ToLower(host)
	if ip, exist := p.store.GetByHost(host); exist {
		return ip
	}

	ip := p.get(host)
	p.store.PutByHost(host, ip)
	return ip
}

// LookBack return host with the fake ip
func (p *Pool) LookBack(ip netip.Addr) (string, bool) {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.settleLocked()

	return p.store.GetByIP(ip)
}

// Exist returns if given ip exists in fake-ip pool
func (p *Pool) Exist(ip netip.Addr) bool {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.settleLocked()

	return p.store.Exist(ip)
}

// Gateway return gateway ip
func (p *Pool) Gateway() netip.Addr {
	return p.gateway
}

// Broadcast return the last ip
func (p *Pool) Broadcast() netip.Addr {
	return p.last
}

// IPNet return raw ipnet
func (p *Pool) IPNet() netip.Prefix {
	return p.ipnet
}

// CloneFrom clone cache from old pool
func (p *Pool) CloneFrom(o *Pool) {
	if p.first == o.first && p.last == o.last && sameStoreKind(p.store, o.store) {
		p.allocator = o.allocator
		return
	}
	p.mux.Lock()
	defer p.mux.Unlock()

	o.mux.Lock()
	defer o.mux.Unlock()
	o.settleLocked()
	o.retired = true
	o.store.CloneTo(p.store)

	// the allocation state only matches the cloned entries if both pools cover the same range
	if o.first == p.first && o.last == p.last {
		p.settleLocked()
		p.offset, p.cycle = o.offset, o.cycle
	}
}

func sameStoreKind(a, b store) bool {
	switch a.(type) {
	case *memoryStore:
		_, ok := b.(*memoryStore)
		return ok
	case *cachefileStore:
		_, ok := b.(*cachefileStore)
		return ok
	}
	return false
}

func (p *Pool) settleLocked() {
	if p.flushPending {
		p.flushPending = false
		_ = p.flushLocked()
	}
}

func (p *Pool) get(host string) netip.Addr {
	p.offset = p.offset.Next()

	if !p.offset.Less(p.last) {
		p.cycle = true
		p.offset = p.first
	}

	if p.cycle || p.store.Exist(p.offset) {
		if owner, held := p.store.GetByIP(p.offset); held {
			if p.cycle {
				log.Debugln("[FakeIP] %v reissued: %s takes it from %s (the range is cycling)", p.offset, host, owner)
			} else {
				log.Warnln("[FakeIP] %v reissued: %s takes it from %s", p.offset, host, owner)
			}
		}
		p.store.DelByIP(p.offset)
	}

	p.store.PutByIP(p.offset, host)
	p.persistPositionLocked()
	return p.offset
}

func (p *Pool) persistPositionLocked() {
	if p.retired {
		return
	}
	if s, ok := p.store.(*cachefileStore); ok {
		s.PutByHost(offsetKey, p.offset)
		if p.cycle {
			s.PutByHost(cycleKey, p.offset)
		}
	}
}

func (p *Pool) FlushFakeIP() error {
	p.mux.Lock()
	defer p.mux.Unlock()
	return p.flushLocked()
}

func (p *Pool) flushLocked() error {
	err := p.store.FlushFakeIP()
	if err == nil {
		p.cycle = false
		p.offset = p.first.Prev()
		p.flushPending = false
	}
	return err
}

func (p *Pool) StoreState() {
	p.mux.Lock()
	defer p.mux.Unlock()
	if p.flushPending || p.retired {
		return
	}
	if s, ok := p.store.(*cachefileStore); ok {
		s.PutByHost(offsetKey, p.offset)
		if p.cycle {
			s.PutByHost(cycleKey, p.offset)
		}
		s.Sync()
	}
}

func (p *Pool) restoreState() {
	if s, ok := p.store.(*cachefileStore); ok {
		if _, exist := s.GetByHost(cycleKey); exist {
			p.cycle = true
		}

		if offset, exist := s.GetByHost(offsetKey); exist {
			if p.ipnet.Contains(offset) {
				p.offset = offset
				if !p.cycle {
					p.skipMappedPastOffset(s)
				}
				log.Infoln("[FakeIP] %v: resuming after %v (cycling %v)", p.ipnet, p.offset, p.cycle)
			} else {
				p.cycle, p.flushPending = false, true
				log.Infoln("[FakeIP] %v: the file's position %v is outside this range; it is emptied on first use", p.ipnet, offset)
			}
		} else if s.Exist(p.first) {
			p.cycle, p.flushPending = false, true
			log.Infoln("[FakeIP] %v: the file has mappings but no position; it is emptied on first use", p.ipnet)
		}
	}
}

func (p *Pool) skipMappedPastOffset(s *cachefileStore) {
	from := p.offset
	for next := p.offset.Next(); next.Less(p.last) && s.Exist(next); next = next.Next() {
		p.offset = next
	}
	if p.offset != from {
		log.Warnln("[FakeIP] %v: the position on file (%v) is behind addresses already handed out; resuming after %v", p.ipnet, from, p.offset)
	}
}

type Options struct {
	IPNet netip.Prefix

	// Size sets the maximum number of entries in memory
	// and does not work if Persistence is true
	Size int

	// Persistence will save the data to disk.
	// Size will not work and record will be fully stored.
	Persistence bool
}

// New return Pool instance
func New(options Options) (*Pool, error) {
	var (
		hostAddr = options.IPNet.Masked().Addr()
		gateway  = hostAddr.Next()
		first    = gateway.Next().Next().Next() // default start with 198.18.0.4
		last     = netipx.PrefixLastIP(options.IPNet)
	)

	if !options.IPNet.IsValid() || !first.IsValid() || !first.Less(last) {
		return nil, errors.New("ipnet don't have valid ip")
	}

	pool := &Pool{
		gateway: gateway,
		first:   first,
		last:    last,
		ipnet:   options.IPNet,
		allocator: &allocator{
			offset: first.Prev(),
		},
	}
	if options.Persistence {
		pool.store = newCachefileStore(cachefile.Cache(), options.IPNet)
	} else {
		pool.store = newMemoryStore(options.Size)
	}

	pool.restoreState()

	return pool, nil
}
