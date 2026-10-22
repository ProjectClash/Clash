package cachefile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestPersistentCachePathOverridesHomeDir(t *testing.T) {
	if os.Getenv("CLASH_CACHEFILE_PATH_HELPER") == "1" {
		home := t.TempDir()
		private := filepath.Join(t.TempDir(), "cache.db")
		C.SetHomeDir(home)
		if err := SetPersistentCachePath(private); err != nil {
			t.Fatal(err)
		}
		cache := Cache()
		if cache == nil || cache.DB == nil {
			t.Fatal("persistent cache did not open")
		}
		defer cache.Close()
		if got := cache.DB.Path(); got != private {
			t.Fatalf("cache opened at %s, want %s", got, private)
		}
		if _, err := os.Stat(filepath.Join(home, "cache.db")); !os.IsNotExist(err) {
			t.Fatalf("home directory got a cache.db: %v", err)
		}
		if err := SetPersistentCachePath(private); err != nil {
			t.Fatalf("setting the open path again: %v", err)
		}
		if err := SetPersistentCachePath(filepath.Join(home, "cache.db")); err == nil {
			t.Fatal("moving an open cache succeeded")
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPersistentCachePathOverridesHomeDir$")
	command.Env = append(os.Environ(), "CLASH_CACHEFILE_PATH_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}
