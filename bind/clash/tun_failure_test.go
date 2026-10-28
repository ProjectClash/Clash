package clash

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ProjectClash/Clash/listener/sing_tun"
	"golang.org/x/sys/unix"
)

func TestATunFailureReachesThePlatformAndTheDiagnostics(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	recordTunDescriptor(fds[0])
	if got := lastTunFailure(); got != "" {
		t.Fatalf("a new descriptor reads as failed: %q", got)
	}
	platform := newRecordingPlatform()
	reportTunFailure(platform, syscall.EBADF)
	if got := platform.reportedTunFailures(); len(got) != 1 || got[0] != syscall.EBADF.Error() {
		t.Fatalf("the platform was told %q, want the error once", got)
	}
	if got := lastTunFailure(); !strings.HasSuffix(got, " "+syscall.EBADF.Error()) {
		t.Fatalf("diagnostics tunFailure %q, want the time and the error", got)
	}
	recordTunDescriptor(fds[0])
	if got := lastTunFailure(); got != "" {
		t.Fatalf("the next descriptor carries the last one's failure: %q", got)
	}
}

func TestATunStartHandsItsPlatformTheFailureHook(t *testing.T) {
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	base, err := os.MkdirTemp("/tmp", "clash-tunfail-")
	if err != nil {
		t.Fatalf("short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := Setup(&SetupOptions{
		BasePath:    base,
		WorkingPath: filepath.Join(base, "w"),
		TempPath:    filepath.Join(base, "t"),
	}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	platform := &fdPlatform{
		recordingPlatform: recordingPlatform{lines: make(chan string, 256), underNetworkExtension: true},
		fd:                int32(fds[0]),
	}
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	out, err := FinalizeForIOS("tun:\n  enable: true\n  stack: mips\nproxies: []\nrules: ['MATCH,DIRECT']\n", "{}")
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := svc.Start(out.Value); err != nil {
		for {
			select {
			case line := <-platform.lines:
				t.Log(line)
				continue
			default:
			}
			break
		}
		t.Fatalf("Start: %v", err)
	}
	hook := sing_tun.DeviceFailure()
	if hook == nil {
		_ = svc.Close()
		t.Fatal("a start with a tun left sing-tun no failure hook")
	}
	hook(syscall.ENXIO)
	if got := platform.reportedTunFailures(); len(got) != 1 || got[0] != syscall.ENXIO.Error() {
		_ = svc.Close()
		t.Fatalf("the starting service's platform was told %q, want the error once", got)
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sing_tun.DeviceFailure() != nil {
		t.Fatal("the closed service's hook outlived it")
	}
	hook(syscall.EBADF)
	if got := platform.reportedTunFailures(); len(got) != 1 {
		t.Fatalf("a late report of a closed tun reached the platform: %q", got)
	}
}
