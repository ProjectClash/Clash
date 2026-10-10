package fakeip

import (
	"net/netip"
	"testing"
)

func TestAReloadedPoolDoesNotReissueAddressesInUse(t *testing.T) {
	cases := map[string]func(t *testing.T) (old, reloaded func() *Pool){
		"memory": func(t *testing.T) (func() *Pool, func() *Pool) {
			mk := func() *Pool {
				p, err := New(Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 1000})
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
			return mk, mk
		},
		"cache file": func(t *testing.T) (func() *Pool, func() *Pool) {
			cache := openTestCacheSync(t, false)
			mk := func() *Pool { return persistentPool(t, cache, "198.18.0.1/16") }
			return mk, mk
		},
		"cache file with an earlier shutdown": func(t *testing.T) (func() *Pool, func() *Pool) {
			cache := openTestCacheSync(t, false)
			earlier := persistentPool(t, cache, "198.18.0.1/16")
			earlier.Lookup("earlier.example.com")
			earlier.StoreState()
			mk := func() *Pool { return persistentPool(t, cache, "198.18.0.1/16") }
			return mk, mk
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			newOld, newReloaded := setup(t)
			old := newOld()
			given := map[string]netip.Addr{}
			for _, host := range []string{"example.com", "ab.example.com", "cdn.example.net"} {
				given[host] = old.Lookup(host)
			}

			reloaded := newReloaded()
			reloaded.CloneFrom(old)
			sentry := reloaded.Lookup("o33249.ingest.sentry.io")
			for host, ip := range given {
				if sentry == ip {
					t.Errorf("the reloaded pool gave %v, still %s's, to the new name", ip, host)
				}
				if got, ok := reloaded.LookBack(ip); !ok || got != host {
					t.Errorf("%v maps back to %q %v after the reload, want %s", ip, got, ok, host)
				}
				if got := reloaded.Lookup(host); got != ip {
					t.Errorf("%s is %v after the reload, was %v", host, got, ip)
				}
			}
		})
	}
}

func TestAFlushReachesBothPoolsOfAReload(t *testing.T) {
	ipnet := netip.MustParsePrefix("198.18.0.1/16")
	old, _ := New(Options{IPNet: ipnet, Size: 10})
	given := old.Lookup("example.com")
	reloaded, _ := New(Options{IPNet: ipnet, Size: 10})
	reloaded.CloneFrom(old)
	if err := reloaded.FlushFakeIP(); err != nil {
		t.Fatal(err)
	}
	if _, ok := old.LookBack(given); ok {
		t.Fatalf("the old pool still maps %v after the flush", given)
	}
	a, b := old.Lookup("a.example.com"), reloaded.Lookup("b.example.com")
	if a == b || a != given {
		t.Fatalf("after the flush the pools gave %v and %v, want %v and the next", a, b, given)
	}
}

func TestAPendingFlushTheFileRefusesIsTriedOnce(t *testing.T) {
	cache := openTestCacheSync(t, false)
	running := persistentPool(t, cache, "198.18.0.1/16")
	running.Lookup("example.com")
	running.StoreState()
	candidate := persistentPool(t, cache, "198.19.0.1/16")
	if !candidate.flushPending {
		t.Fatal("the candidate has nothing pending; the test proves nothing")
	}
	_ = cache.DB.Close()
	candidate.Exist(netip.MustParseAddr("198.19.0.4"))
	if candidate.flushPending {
		t.Fatal("a refused flush is still pending, to be retried by the next query")
	}
}

func TestAReloadIntoAnotherRangeStartsAtItsBeginning(t *testing.T) {
	old, _ := New(Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 10})
	old.Lookup("a.example.com")
	old.Lookup("b.example.com")
	reloaded, _ := New(Options{IPNet: netip.MustParsePrefix("198.19.0.1/16"), Size: 10})
	reloaded.CloneFrom(old)
	if got := reloaded.Lookup("c.example.com"); got != netip.MustParseAddr("198.19.0.4") {
		t.Fatalf("first name in the new range got %v", got)
	}
}

func TestBuildingAReloadedPoolLeavesTheCacheFileAlone(t *testing.T) {
	cache := openTestCacheSync(t, false)
	old := persistentPool(t, cache, "198.18.0.1/16")
	ip := old.Lookup("example.com")

	_ = persistentPool(t, cache, "198.18.0.1/16")
	if host, ok := old.LookBack(ip); !ok || host != "example.com" {
		t.Fatalf("building a second pool on the file lost %v: %q %v", ip, host, ok)
	}
}

func TestTheOldPoolAnsweringAfterTheReloadDoesNotCollide(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T) func() *Pool{
		"memory": func(t *testing.T) func() *Pool {
			return func() *Pool {
				p, _ := New(Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 1000})
				return p
			}
		},
		"cache file": func(t *testing.T) func() *Pool {
			cache := openTestCacheSync(t, false)
			return func() *Pool { return persistentPool(t, cache, "198.18.0.1/16") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			build := mk(t)
			old := build()
			old.Lookup("before.example.com")
			reloaded := build()
			reloaded.CloneFrom(old)

			late := old.Lookup("example.com")
			other := reloaded.Lookup("o33249.ingest.sentry.io")
			if other == late {
				t.Fatalf("both pools gave %v", late)
			}
			if host, ok := reloaded.LookBack(late); !ok || host != "example.com" {
				t.Fatalf("the reloaded pool maps %v, given late by the old one, to %q %v", late, host, ok)
			}
		})
	}
}

func TestTheSameRangeWrittenDifferentlyIsTheSamePool(t *testing.T) {
	old, _ := New(Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 1000})
	given := old.Lookup("example.com")
	reloaded, _ := New(Options{IPNet: netip.MustParsePrefix("198.18.0.0/16"), Size: 1000})
	reloaded.CloneFrom(old)
	if got := reloaded.Lookup("o33249.ingest.sentry.io"); got == given {
		t.Fatalf("the reloaded pool gave %v, example.com's, again", got)
	}
}

func TestACandidateInAnotherRangeEmptiesTheFileOnlyWhenUsed(t *testing.T) {
	cache := openTestCacheSync(t, false)
	running := persistentPool(t, cache, "198.18.0.1/16")
	ip := running.Lookup("example.com")
	running.StoreState()

	candidate := persistentPool(t, cache, "198.19.0.1/16")
	if host, ok := running.LookBack(ip); !ok || host != "example.com" {
		t.Fatalf("building the candidate lost %v: %q %v", ip, host, ok)
	}
	candidate.StoreState()
	if host, ok := running.LookBack(ip); !ok || host != "example.com" {
		t.Fatalf("storing the unused candidate lost %v: %q %v", ip, host, ok)
	}

	if got := candidate.Lookup("example.com"); !netip.MustParsePrefix("198.19.0.0/16").Contains(got) {
		t.Fatalf("the candidate in use answered %v, outside its range", got)
	}
}

func TestAnOldPoolsPendingFlushDoesNotEraseTheNewRange(t *testing.T) {
	cache := openTestCacheSync(t, false)
	legacy := cache.FakeIpStore()
	legacy.PutByIP(netip.MustParseAddr("198.18.0.4"), "legacy.example.com")
	legacy.PutByHost("legacy.example.com", netip.MustParseAddr("198.18.0.4"))

	old := persistentPool(t, cache, "198.18.0.1/16")
	if !old.flushPending {
		t.Fatal("the old pool has nothing pending; the test proves nothing")
	}
	reloaded := persistentPool(t, cache, "198.19.0.1/16")
	reloaded.CloneFrom(old)
	ip := reloaded.Lookup("example.com")

	old.Lookup("late.example.com")
	if host, ok := reloaded.LookBack(ip); !ok || host != "example.com" {
		t.Fatalf("a late query on the old pool erased %v: %q %v", ip, host, ok)
	}
}
