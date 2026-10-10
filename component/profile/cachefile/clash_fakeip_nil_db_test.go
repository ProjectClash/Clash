package cachefile

import "testing"

func TestFlushingWithoutACacheFileDoesNotPanic(t *testing.T) {
	store := (&CacheFile{}).FakeIpStore()
	if err := store.FlushFakeIP(); err != nil {
		t.Fatalf("FlushFakeIP with no cache file: %v", err)
	}
}
