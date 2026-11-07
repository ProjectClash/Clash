//go:build unix

package cachefile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ProjectClash/Clash/component/profile"
)

func TestReleaseLetsGoOfTheFileUntilReopen(t *testing.T) {
	if os.Getenv("CLASH_CACHEFILE_RELEASE_HELPER") == "1" {
		runReleaseHelper(t, os.Getenv("CLASH_CACHEFILE_RELEASE_DIR"))
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestReleaseLetsGoOfTheFileUntilReopen$")
	command.Env = append(os.Environ(),
		"CLASH_CACHEFILE_RELEASE_HELPER=1",
		"CLASH_CACHEFILE_RELEASE_DIR="+t.TempDir(),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func runReleaseHelper(t *testing.T, dir string) {
	profile.StoreSelected.Store(true)
	path := filepath.Join(dir, "cache.db")
	if err := SetPersistentCachePath(path); err != nil {
		t.Fatal(err)
	}
	opened := Cache()
	if opened.DB == nil {
		t.Fatal("the cache did not open")
	}
	opened.SetSelected("pick", "b")
	if !fileLocked(t, path) {
		t.Fatal("an open cache does not hold its file's lock")
	}

	if err := Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if fileLocked(t, path) {
		t.Fatal("Release returned with the file still locked")
	}
	if Cache().DB != nil {
		t.Fatal("Cache hands out an open database while released")
	}
	Cache().SetSelected("pick", "a")
	if fileLocked(t, path) {
		t.Fatal("a write after Release took the lock back")
	}
	if got := opened.SelectedMap(); len(got) != 0 {
		t.Fatalf("the closed cache still reads %v", got)
	}
	if err := Release(); err != nil {
		t.Fatalf("a second Release: %v", err)
	}

	Reopen()
	reopened := Cache()
	if reopened.DB == nil {
		t.Fatal("Reopen did not open the cache again")
	}
	if got := reopened.DB.Path(); got != path {
		t.Fatalf("reopened at %s, want %s", got, path)
	}
	if !fileLocked(t, path) {
		t.Fatal("the reopened cache does not hold its file's lock")
	}
	if got := reopened.SelectedMap()["pick"]; got != "b" {
		t.Fatalf("the reopened cache selects %q, want the b written before the release", got)
	}
	Reopen()
	if Cache() != reopened {
		t.Fatal("Reopen without a Release replaced the open cache")
	}
	if err := SetPersistentCachePath(path); err != nil {
		t.Fatalf("setting the path in use again: %v", err)
	}
	if err := SetPersistentCachePath(filepath.Join(dir, "other.db")); err == nil {
		t.Fatal("the path of an opened cache was changed")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func fileLocked(t *testing.T, path string) bool {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return false
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	t.Fatalf("flock %s: %v", path, err)
	return false
}
