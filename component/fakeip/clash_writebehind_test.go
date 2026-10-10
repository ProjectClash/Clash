package fakeip

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/profile/cachefile"

	"github.com/metacubex/bbolt"
)

func openTestCache(t *testing.T) *cachefile.CacheFile {
	t.Helper()
	return openTestCacheSync(t, true)
}

func openTestCacheSync(t *testing.T, sync bool) *cachefile.CacheFile {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fakeip")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	db, err := bbolt.Open(f.Name(), 0o666, &bbolt.Options{Timeout: time.Second, NoStatistics: true, NoSync: !sync})
	if err != nil {
		t.Fatal(err)
	}
	if !sync {
		db.MaxBatchDelay = time.Microsecond
	}
	t.Cleanup(func() { _ = db.Close() })
	return &cachefile.CacheFile{DB: db}
}

func persistentPool(t *testing.T, cache *cachefile.CacheFile, prefix string) *Pool {
	t.Helper()
	pool, err := New(Options{IPNet: netip.MustParsePrefix(prefix)})
	if err != nil {
		t.Fatal(err)
	}
	pool.store = newCachefileStore(cache, pool.ipnet)
	pool.restoreState()
	return pool
}

func TestNewNamesAreAnsweredWithoutWaitingForTheDisk(t *testing.T) {
	pool := persistentPool(t, openTestCache(t), "198.18.0.1/16")
	const names = 50
	began := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < names; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pool.Lookup(fmt.Sprintf("name-%d.example.com", i))
		}(i)
	}
	wg.Wait()
	if took := time.Since(began); took > 100*time.Millisecond {
		t.Fatalf("%d new names took %s: the answers waited for the disk", names, took)
	}
}

func TestMappingsReachTheDisk(t *testing.T) {
	cache := openTestCache(t)
	pool := persistentPool(t, cache, "198.18.0.1/16")
	ip := pool.Lookup("later.example.com")
	store := cache.FakeIpStore()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := store.GetByHost("later.example.com"); ok && got == ip {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got, ok := store.GetByHost("later.example.com"); !ok || got != ip {
		t.Fatalf("the mapping never reached the disk: %v %v, want %v", got, ok, ip)
	}
	if host, ok := store.GetByIP(ip); !ok || host != "later.example.com" {
		t.Fatalf("the reverse mapping never reached the disk: %q %v", host, ok)
	}

	now := pool.Lookup("at-shutdown.example.com")
	pool.StoreState()
	if got, ok := store.GetByHost("at-shutdown.example.com"); !ok || got != now {
		t.Fatalf("StoreState returned before the pending mapping was on disk: %v %v", got, ok)
	}
}

func TestAReloadedPoolSeesMappingsNotYetOnDisk(t *testing.T) {
	cache := openTestCache(t)
	earlier := persistentPool(t, cache, "198.18.0.1/16")
	earlier.Lookup("earlier.example.com")
	earlier.StoreState()

	old := persistentPool(t, cache, "198.18.0.1/16")
	ip := old.Lookup("in-flight.example.com")

	reloaded := persistentPool(t, cache, "198.18.0.1/16")
	reloaded.CloneFrom(old)
	if host, ok := reloaded.LookBack(ip); !ok || host != "in-flight.example.com" {
		t.Fatalf("the reloaded pool cannot map %v back: %q %v", ip, host, ok)
	}
	if got := reloaded.Lookup("in-flight.example.com"); got != ip {
		t.Fatalf("the reloaded pool answered %v for a name already given %v", got, ip)
	}
}

func TestAWriteTheFileRefusesCostsOnlyItself(t *testing.T) {
	cache := openTestCache(t)
	pool := persistentPool(t, cache, "198.18.0.1/16")
	good := pool.Lookup("good.example.com")
	pool.Lookup("")
	pool.StoreState()

	if got, ok := cache.FakeIpStore().GetByHost("good.example.com"); !ok || got != good {
		t.Fatalf("a refused write took good.example.com off the disk with it: %v %v", got, ok)
	}
	pool.Lookup("after.example.com")
	pool.StoreState()
	if host, ok := pool.LookBack(good); !ok || host != "good.example.com" {
		t.Fatalf("the address %v handed out for good.example.com no longer maps back: %q %v", good, host, ok)
	}
}

func TestWithoutACacheFileNothingIsStoredAndNothingPanics(t *testing.T) {
	cache := &cachefile.CacheFile{}
	pool := persistentPool(t, cache, "198.18.0.1/16")
	ip := pool.Lookup("nowhere.example.com")
	if host, ok := pool.LookBack(ip); ok {
		t.Fatalf("with no cache file a mapping was found: %q", host)
	}
	reloaded := persistentPool(t, cache, "198.18.0.1/16")
	reloaded.CloneFrom(pool)
	reloaded.StoreState()
}

func TestTheStoreAnswersAsTheDirectWritesDid(t *testing.T) {
	hosts := []string{"a.com", "b.com", "c.com", "d.com", "", "e.com"}
	ips := []netip.Addr{
		netip.MustParseAddr("198.18.0.4"), netip.MustParseAddr("198.18.0.5"),
		netip.MustParseAddr("198.18.0.6"), netip.MustParseAddr("198.18.0.7"),
	}
	for seed := int64(1); seed <= 100; seed++ {
		random := rand.New(rand.NewSource(seed))
		direct := openTestCacheSync(t, false).FakeIpStore()
		behind := newCachefileStore(openTestCacheSync(t, false), netip.MustParsePrefix("198.18.0.1/16"))
		for step := 0; step < 80; step++ {
			host, ip := hosts[random.Intn(len(hosts))], ips[random.Intn(len(ips))]
			switch random.Intn(5) {
			case 0:
				direct.PutByHost(host, ip)
				behind.PutByHost(host, ip)
			case 1:
				direct.PutByIP(ip, host)
				behind.PutByIP(ip, host)
			case 2:
				direct.DelByIP(ip)
				behind.DelByIP(ip)
			case 3:
				behind.Sync()
			}
			for _, h := range hosts {
				wantIP, wantOK := direct.GetByHost(h)
				if gotIP, gotOK := behind.GetByHost(h); gotOK != wantOK || (wantOK && gotIP != wantIP) {
					t.Fatalf("seed %d step %d: GetByHost(%q) = %v %v, direct writes say %v %v", seed, step, h, gotIP, gotOK, wantIP, wantOK)
				}
			}
			for _, a := range ips {
				wantHost, wantOK := direct.GetByIP(a)
				if gotHost, gotOK := behind.GetByIP(a); gotOK != wantOK || gotHost != wantHost {
					t.Fatalf("seed %d step %d: GetByIP(%v) = %q %v, direct writes say %q %v", seed, step, a, gotHost, gotOK, wantHost, wantOK)
				}
			}
		}
		behind.Sync()
		for _, h := range hosts {
			wantIP, wantOK := direct.GetByHost(h)
			if gotIP, gotOK := behind.cache.GetByHost(h); gotOK != wantOK || (wantOK && gotIP != wantIP) {
				t.Fatalf("seed %d: on disk GetByHost(%q) = %v %v, direct writes say %v %v", seed, h, gotIP, gotOK, wantIP, wantOK)
			}
		}
	}
}

func TestARolledBackBatchIsWrittenOneByOne(t *testing.T) {
	cache := openTestCache(t)
	store := newCachefileStore(cache, netip.MustParsePrefix("198.18.0.1/16"))
	good := netip.MustParseAddr("198.18.0.9")
	store.PutByHost(strings.Repeat("x", bbolt.MaxKeySize+1), netip.MustParseAddr("198.18.0.8"))
	store.PutByHost("good.example.com", good)
	store.PutByIP(good, "good.example.com")
	store.Sync()
	if got, ok := cache.FakeIpStore().GetByHost("good.example.com"); !ok || got != good {
		t.Fatalf("a refused op took the rest of its batch with it: %v %v", got, ok)
	}
	if host, ok := cache.FakeIpStore().GetByIP(good); !ok || host != "good.example.com" {
		t.Fatalf("a refused op took the reverse mapping with it: %q %v", host, ok)
	}
}
