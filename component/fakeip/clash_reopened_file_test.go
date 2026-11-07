package fakeip

import (
	"testing"

	"github.com/ProjectClash/Clash/component/profile/cachefile"
)

func TestAPoolClonedAcrossAReopenedFileUsesTheReopenedFile(t *testing.T) {
	k := newKillableCache(t)
	before := persistentPool(t, &cachefile.CacheFile{DB: k.db}, "198.18.0.1/16")
	given := before.Lookup("before.example.com")
	before.StoreState()
	_ = k.db.Close()
	reopened := k.open()

	after := persistentPool(t, reopened, "198.18.0.1/16")
	after.CloneFrom(before)

	if host, ok := after.LookBack(given); !ok || host != "before.example.com" {
		t.Fatalf("%v maps to %q (found %v) after the reopen, want before.example.com", given, host, ok)
	}
	next := after.Lookup("after.example.com")
	if next == given {
		t.Fatalf("after.example.com was handed %v, which before.example.com still holds", next)
	}
	after.store.(*cachefileStore).Sync()
	if host, ok := reopened.FakeIpStore().GetByIP(next); !ok || host != "after.example.com" {
		t.Fatalf("the reopened file maps %v to %q (found %v), want after.example.com", next, host, ok)
	}
}
