package clash

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/ProjectClash/Clash/component/profile/cachefile"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
)

const persistentCacheReleaseYAML = `
mode: rule
log-level: info
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 8.8.8.8
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: b, type: socks5, server: 127.0.0.1, port: 1081}
proxy-groups:
  - name: pick
    type: select
    proxies: [a, b]
rules:
  - MATCH,pick
`

func TestCloseLetsGoOfThePersistentCacheAndStartTakesItBack(t *testing.T) {
	if os.Getenv("CLASH_CACHE_RELEASE_HELPER") == "1" {
		runPersistentCacheReleaseHelper(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCloseLetsGoOfThePersistentCacheAndStartTakesItBack$")
	command.Env = append(os.Environ(),
		"CLASH_CACHE_RELEASE_HELPER=1",
		"CLASH_CACHE_RELEASE_BASE="+t.TempDir(),
		"CLASH_CACHE_RELEASE_PRIVATE="+t.TempDir(),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func runPersistentCacheReleaseHelper(t *testing.T) {
	base := os.Getenv("CLASH_CACHE_RELEASE_BASE")
	private := os.Getenv("CLASH_CACHE_RELEASE_PRIVATE")
	opts := &SetupOptions{
		BasePath:                 base,
		WorkingPath:              filepath.Join(base, "working"),
		TempPath:                 filepath.Join(base, "temp"),
		PersistentCacheDirectory: private,
	}
	if err := Setup(opts); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "cache.db")
	host, ip := "cache-release.example", netip.MustParseAddr("198.18.0.42")

	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(persistentCacheReleaseYAML); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if !cacheFileLocked(t, path) {
		t.Fatal("a running core does not hold the cache it keeps its state in")
	}
	if err := SelectProxy("pick", "b"); err != nil {
		t.Fatal(err)
	}
	store := cachefile.Cache().FakeIpStore()
	store.PutByHost(host, ip)
	store.PutByIP(ip, host)
	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if cacheFileLocked(t, path) {
		t.Fatal("Close returned with cache.db still locked; a stopped tunnel must hold no file lock")
	}
	cachefile.Cache().SetSelected("pick", "a")
	if cacheFileLocked(t, path) {
		t.Fatal("a write after Close took the cache.db lock back")
	}

	if err := svc.Start(persistentCacheReleaseYAML); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if !cacheFileLocked(t, path) {
		t.Fatal("the second Start did not open the cache again")
	}
	if got := cachefile.Cache().DB.Path(); got != path {
		t.Fatalf("the second Start opened %s, want %s", got, path)
	}
	group, ok := tunnel.Proxies()["pick"]
	if !ok {
		t.Fatal("no pick group after the second Start")
	}
	selector, ok := group.Adapter().(interface{ Now() string })
	if !ok {
		t.Fatalf("pick is a %T", group.Adapter())
	}
	if got := selector.Now(); got != "b" {
		t.Fatalf("pick selects %q after the restart, want the b chosen before the stop", got)
	}
	if got, found := resolver.FindHostByIP(ip); !found || got != host {
		t.Fatalf("fake-ip %s maps to %q (found %v) after the restart, want %s", ip, got, found, host)
	}
}

func TestWhatTheCacheReleaseWritesReachesThePlatformLog(t *testing.T) {
	if os.Getenv("CLASH_CACHE_RELEASE_LOG_HELPER") == "1" {
		runCacheReleaseLogHelper(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestWhatTheCacheReleaseWritesReachesThePlatformLog$")
	command.Env = append(os.Environ(),
		"CLASH_CACHE_RELEASE_LOG_HELPER=1",
		"CLASH_CACHE_RELEASE_BASE="+t.TempDir(),
		"CLASH_CACHE_RELEASE_PRIVATE="+t.TempDir(),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func runCacheReleaseLogHelper(t *testing.T) {
	base := os.Getenv("CLASH_CACHE_RELEASE_BASE")
	if err := Setup(&SetupOptions{
		BasePath:                 base,
		WorkingPath:              filepath.Join(base, "working"),
		TempPath:                 filepath.Join(base, "temp"),
		PersistentCacheDirectory: os.Getenv("CLASH_CACHE_RELEASE_PRIVATE"),
	}); err != nil {
		t.Fatal(err)
	}
	const probe = "cache release log probe"
	cachefile.OnRelease(func(*cachefile.CacheFile) { log.Warnln("[Apple] %s", probe) })
	platform := &collectingLogPlatform{recordingPlatform: newRecordingPlatform()}
	svc, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(persistentCacheReleaseYAML); err != nil {
		t.Fatalf("Start: %v", err)
	}
	svc.logWriter.markTunnelEstablished()
	platform.holdUntil(svc.logWriter.done)
	for i := range 20 {
		log.Warnln("[Apple] a line ahead of the stop, %d", i)
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !platform.wrote(probe) {
		t.Fatal("a line the cache release wrote did not reach the platform log")
	}
}

type collectingLogPlatform struct {
	*recordingPlatform
	mu    sync.Mutex
	hold  <-chan struct{}
	lines []string
}

func (p *collectingLogPlatform) holdUntil(released <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hold = released
}

func (p *collectingLogPlatform) WriteLog(message string) {
	p.mu.Lock()
	hold := p.hold
	p.hold = nil
	p.mu.Unlock()
	if hold != nil {
		<-hold
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lines = append(p.lines, message)
}

func (p *collectingLogPlatform) wrote(text string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, line := range p.lines {
		if strings.Contains(line, text) {
			return true
		}
	}
	return false
}

func cacheFileLocked(t *testing.T, path string) bool {
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
