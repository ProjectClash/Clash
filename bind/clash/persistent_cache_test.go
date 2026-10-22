package clash

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/profile/cachefile"
)

func runPersistentCachePhase(t *testing.T, phase, base, private string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestPersistentCacheHelper$")
	command.Env = append(os.Environ(),
		"CLASH_PERSISTENT_CACHE_PHASE="+phase,
		"CLASH_PERSISTENT_CACHE_BASE="+base,
		"CLASH_PERSISTENT_CACHE_PRIVATE="+private,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("phase %s failed: %v\n%s", phase, err, output)
	}
}

func TestPersistentCacheHelper(t *testing.T) {
	phase := os.Getenv("CLASH_PERSISTENT_CACHE_PHASE")
	if phase == "" {
		t.Skip("helper for the persistent cache tests")
	}
	base := os.Getenv("CLASH_PERSISTENT_CACHE_BASE")
	private := os.Getenv("CLASH_PERSISTENT_CACHE_PRIVATE")
	opts := &SetupOptions{
		BasePath:    base,
		WorkingPath: filepath.Join(base, "working"),
		TempPath:    filepath.Join(base, "temp"),
	}
	switch phase {
	case "legacy":
		if err := Setup(opts); err != nil {
			t.Fatal(err)
		}
		cachefile.Cache().SetSelected("GLOBAL", "singapore")
	case "private":
		opts.PersistentCacheDirectory = private
		if err := Setup(opts); err != nil {
			t.Fatal(err)
		}
		cache := cachefile.Cache()
		if cache.DB == nil {
			t.Fatal("persistent cache did not open")
		}
		if got, want := cache.DB.Path(), filepath.Join(private, "cache.db"); got != want {
			t.Fatalf("cache opened at %s, want %s", got, want)
		}
		if got := cache.SelectedMap()["GLOBAL"]; got != "singapore" {
			t.Fatalf("selection after the move = %q, want singapore", got)
		}
		file, err := os.Open(cache.DB.Path())
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Fatalf("flock on the private cache = %v, want EWOULDBLOCK", err)
		}
	case "moved-log":
		opts.PersistentCacheDirectory = private
		if err := Setup(opts); err != nil {
			t.Fatal(err)
		}
		platform := newRecordingPlatform()
		if _, err := NewService(platform); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(5 * time.Second)
		for {
			select {
			case line := <-platform.lines:
				if strings.Contains(line, "cache.db moved from") {
					return
				}
			case <-deadline:
				t.Fatal("the line Setup wrote for the move never reached the platform")
			}
		}
	case "app":
		opts.PersistentCacheDirectory = private
		opts.DisablePersistentCache = true
		if err := Setup(opts); err != nil {
			t.Fatal(err)
		}
		if cachefile.Cache().DB != nil {
			t.Fatal("the App opened a persistent cache")
		}
	default:
		t.Fatalf("unknown phase %q", phase)
	}
}

func TestPersistentCacheMovesOutOfTheAppGroup(t *testing.T) {
	base, private := t.TempDir(), t.TempDir()
	legacy := filepath.Join(base, "working", "cache.db")
	runPersistentCachePhase(t, "legacy", base, private)
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy phase left no cache.db in the App Group: %v", err)
	}
	runPersistentCachePhase(t, "private", base, private)
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("cache.db still in the App Group after the move: %v", err)
	}

	if err := os.WriteFile(legacy, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	runPersistentCachePhase(t, "private", base, private)
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("stale cache.db still in the App Group: %v", err)
	}
}

func TestPersistentCacheMoveReachesThePlatformLog(t *testing.T) {
	base, private := t.TempDir(), t.TempDir()
	runPersistentCachePhase(t, "legacy", base, private)
	runPersistentCachePhase(t, "moved-log", base, private)
}

func TestPersistentCacheIsNotMovedByTheApp(t *testing.T) {
	base, private := t.TempDir(), t.TempDir()
	legacy := filepath.Join(base, "working", "cache.db")
	runPersistentCachePhase(t, "legacy", base, private)
	runPersistentCachePhase(t, "app", base, private)
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("the App moved the tunnel's cache.db: %v", err)
	}
	if _, err := os.Stat(filepath.Join(private, "cache.db")); !os.IsNotExist(err) {
		t.Fatalf("the App created a cache.db: %v", err)
	}
}

func TestPersistentCacheCopyKeepsTheBytes(t *testing.T) {
	legacy := filepath.Join(t.TempDir(), "cache.db")
	target := filepath.Join(t.TempDir(), "cache.db")
	want := []byte("bbolt pages")
	if err := os.WriteFile(legacy, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyLegacyPersistentCache(legacy, target); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(want) {
		t.Fatalf("copied %q (%v), want %q", got, err, want)
	}
	if _, err := os.Stat(target + ".moving"); !os.IsNotExist(err) {
		t.Fatalf("partial copy left behind: %v", err)
	}

	if err := copyLegacyPersistentCache(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "cache.db")); err == nil {
		t.Fatal("copying a missing cache succeeded")
	}
}
