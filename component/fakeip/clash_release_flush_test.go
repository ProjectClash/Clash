package fakeip

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/component/profile/cachefile"
)

func TestReleaseWritesWhatIsPendingAndDropsTheClosedWriteBehind(t *testing.T) {
	if os.Getenv("CLASH_FAKEIP_RELEASE_HELPER") == "1" {
		runReleaseFlushHelper(t, os.Getenv("CLASH_FAKEIP_RELEASE_DIR"))
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestReleaseWritesWhatIsPendingAndDropsTheClosedWriteBehind$")
	command.Env = append(os.Environ(),
		"CLASH_FAKEIP_RELEASE_HELPER=1",
		"CLASH_FAKEIP_RELEASE_DIR="+t.TempDir(),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func runReleaseFlushHelper(t *testing.T, dir string) {
	if err := cachefile.SetPersistentCachePath(filepath.Join(dir, "cache.db")); err != nil {
		t.Fatal(err)
	}
	cache := cachefile.Cache()
	if cache.DB == nil {
		t.Fatal("the cache did not open")
	}
	pool := persistentPool(t, cache, "198.18.0.1/16")
	given := pool.Lookup("pending.example.com")
	key := cache.FakeIpStore().Key()
	closing := pool.store.(*cachefileStore).pending

	if err := cachefile.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	writeBehindsMu.Lock()
	_, kept := writeBehinds[key]
	writeBehindsMu.Unlock()
	if kept {
		t.Fatal("the closed file's write-behind is still registered")
	}
	pool.Lookup("late.example.com")
	closing.mu.Lock()
	armed, queued, held := closing.armed, len(closing.ops), len(closing.hosts)+len(closing.ips)
	closing.mu.Unlock()
	if armed || queued != 0 || held != 0 {
		t.Fatalf("a lookup after the release queued %d writes for the closed file (timer armed %v) and holds %d records", queued, armed, held)
	}

	cachefile.Reopen()
	reopened := cachefile.Cache()
	if reopened.DB == nil {
		t.Fatal("the cache did not open again")
	}
	if ip, ok := reopened.FakeIpStore().GetByHost("pending.example.com"); !ok || ip != given {
		t.Fatalf("pending.example.com reads %v (found %v) after the release, want %v", ip, ok, given)
	}
}
