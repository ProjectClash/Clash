package fakeip

import (
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/profile/cachefile"

	"github.com/metacubex/bbolt"
)


type killableCache struct {
	t    *testing.T
	path string
	db   *bbolt.DB
}

func newKillableCache(t *testing.T) *killableCache {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fakeip")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	k := &killableCache{t: t, path: f.Name()}
	k.open()
	t.Cleanup(func() { _ = k.db.Close() })
	return k
}

func (k *killableCache) open() *cachefile.CacheFile {
	db, err := bbolt.Open(k.path, 0o666, &bbolt.Options{Timeout: time.Second, NoStatistics: true, NoSync: true})
	if err != nil {
		k.t.Fatal(err)
	}
	db.MaxBatchDelay = time.Microsecond
	k.db = db
	return &cachefile.CacheFile{DB: db}
}

func (k *killableCache) kill(p *Pool) *cachefile.CacheFile {
	p.store.(*cachefileStore).Sync()
	_ = k.db.Close()
	return k.open()
}

func TestAStartAfterAKillDoesNotReissueAddressesInUse(t *testing.T) {
	k := newKillableCache(t)
	cache := &cachefile.CacheFile{DB: k.db}

	before := persistentPool(t, cache, "198.18.0.1/16")
	before.Lookup("before.example.com")
	before.StoreState()
	_ = k.db.Close()
	cache = k.open()

	killed := persistentPool(t, cache, "198.18.0.1/16")
	given := map[string]netip.Addr{}
	for _, host := range []string{"ios.chat.example.org", "telemetry.example.net", "ws.example.com", "ab.example.com"} {
		given[host] = killed.Lookup(host)
	}
	cache = k.kill(killed)

	next := persistentPool(t, cache, "198.18.0.1/16")
	for i := 0; i < 8; i++ {
		host := fmt.Sprintf("new-%d.example.org", i)
		ip := next.Lookup(host)
		for owner, held := range given {
			if ip == held {
				t.Errorf("%s was given %v, which the killed run gave %s", host, ip, owner)
			}
		}
	}
	for host, ip := range given {
		if got, ok := next.LookBack(ip); !ok || got != host {
			t.Errorf("%v maps back to %q %v after the kill, want %s", ip, got, ok, host)
		}
	}
}

func TestAStartAfterAKillKeepsCycling(t *testing.T) {
	k := newKillableCache(t)
	cache := &cachefile.CacheFile{DB: k.db}
	killed := persistentPool(t, cache, "198.18.0.1/29")
	for i := 0; i < 4; i++ {
		killed.Lookup(fmt.Sprintf("n%d.example.com", i))
	}
	if !killed.cycle {
		t.Fatal("fixture: the pool did not cycle")
	}
	last := killed.offset
	cache = k.kill(killed)
	next := persistentPool(t, cache, "198.18.0.1/29")
	if !next.cycle || next.offset != last {
		t.Fatalf("resumed at %v cycle=%v, want %v cycle=true", next.offset, next.cycle, last)
	}
}

func TestTheFirstStartAfterAKilledOlderCoreSkipsItsMappings(t *testing.T) {
	cache := openTestCacheSync(t, false)
	raw := cache.FakeIpStore()
	raw.PutByHost(offsetKey, netip.MustParseAddr("198.18.0.5"))
	held := map[string]netip.Addr{}
	for i, host := range []string{"ios.chat.example.org", "telemetry.example.net", "ab.example.com"} {
		ip := netip.AddrFrom4([4]byte{198, 18, 0, byte(6 + i)})
		raw.PutByIP(ip, host)
		raw.PutByHost(host, ip)
		held[host] = ip
	}

	next := persistentPool(t, cache, "198.18.0.1/16")
	for i := 0; i < 4; i++ {
		ip := next.Lookup(fmt.Sprintf("new-%d.example.org", i))
		for owner, h := range held {
			if ip == h {
				t.Errorf("a new name was given %v, still %s's", ip, owner)
			}
		}
	}
	for host, ip := range held {
		if got, ok := next.LookBack(ip); !ok || got != host {
			t.Errorf("%v maps back to %q %v, want %s", ip, got, ok, host)
		}
	}
}

func TestAnOldPoolAfterARangeChangeDoesNotWriteItsPosition(t *testing.T) {
	k := newKillableCache(t)
	cache := &cachefile.CacheFile{DB: k.db}
	old := persistentPool(t, cache, "198.18.0.1/16")
	old.Lookup("before.example.com")
	reloaded := persistentPool(t, cache, "198.19.0.1/16")
	reloaded.CloneFrom(old)
	ip := reloaded.Lookup("example.com")
	old.Lookup("late.example.com")
	cache = k.kill(reloaded)

	next := persistentPool(t, cache, "198.19.0.1/16")
	if host, ok := next.LookBack(ip); !ok || host != "example.com" {
		t.Fatalf("%v maps back to %q %v after the kill, want example.com", ip, host, ok)
	}
}
