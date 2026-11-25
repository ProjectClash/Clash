package clash

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata"
	"golang.org/x/sys/unix"
)

const breadcrumbReloadDocument = "mode: rule\nlog-level: info\n" +
	"dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver: ['223.5.5.5']\n" +
	"tun:\n  enable: true\n  stack: mips\n" +
	"proxies:\n  - {name: P, type: direct}\n" +
	"rules:\n  - DOMAIN-SUFFIX,example.com,P\n  - MATCH,P\n"

func breadcrumbReloadService(t *testing.T) (*BoxService, string) {
	t.Helper()
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	base, err := os.MkdirTemp("/tmp", "clash-crumb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t"), MemoryLimit: 50 << 20}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	home := filepath.Join(base, "crumb")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	previous, previousRecording := breadcrumbDirectory, breadcrumbRecording.Load()
	breadcrumbDirectory = home
	t.Cleanup(func() {
		breadcrumbDirectory = previous
		setStartupBreadcrumbRecording(previousRecording)
		geodata.SetGeodataProgressReporter(nil)
	})
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	platform := &fdPlatform{recordingPlatform: recordingPlatform{lines: make(chan string, 4096), underNetworkExtension: true}, fd: int32(fds[0])}
	go func() {
		for range platform.lines {
		}
	}()
	service, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	finalized, err := FinalizeForIOS(breadcrumbReloadDocument, "{}")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := service.Start(finalized.Value); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("fixture: a started tunnel already explains a death: %s", explanation)
	}
	return service, home
}

func assertNoStartupRecordAfterReload(t *testing.T, home, what string) {
	t.Helper()
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Errorf("after %s the next launch would read a death that did not happen: %s", what, explanation)
	}
	if _, err := os.Stat(filepath.Join(home, breadcrumbFileName)); !os.IsNotExist(err) {
		t.Errorf("after %s a startup record is still on disk (%v)", what, err)
	}
	if breadcrumbRecording.Load() {
		t.Errorf("after %s the recorder is still armed: a geo resource built later rewrites the record from the matching path", what)
	}
	if geodata.GeodataProgressReporter() != nil {
		t.Errorf("after %s the geodata seam still reports to the startup record", what)
	}
}

func TestAReloadThatAppliesLeavesNoStartupRecord(t *testing.T) {
	service, home := breadcrumbReloadService(t)
	next, err := FinalizeForIOS(breadcrumbReloadDocument+"  - DOMAIN,reloaded.example,P\n", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Reload(next.Value); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	assertNoStartupRecordAfterReload(t, home, "a reload that applied")
}

func TestAReloadThatIsRefusedLeavesNoStartupRecord(t *testing.T) {
	service, home := breadcrumbReloadService(t)
	refused := "mode: rule\ntun:\n  enable: true\n  stack: mips\nproxies:\n  - {name: P, type: direct}\nrules:\n  - DOMAIN,a.example,NoSuchProxy\n  - MATCH,P\n"
	if err := service.Reload(refused); err == nil {
		t.Fatal("fixture: a reload naming a proxy the document does not have was applied")
	}
	assertNoStartupRecordAfterReload(t, home, "a reload that was refused (the running tunnel unchanged)")
}
