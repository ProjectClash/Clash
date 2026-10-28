package clash

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	LC "github.com/ProjectClash/Clash/listener/config"
	"golang.org/x/sys/unix"
)

type fdPlatform struct {
	recordingPlatform
	fd          int32
	gotInet4    string
	gotMTU      int32
	openTunErr  error
	openTunCall int
}

func TestStartSurfacesPacketFlowBridgeDupFailure(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "clash-tun-")
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
	const neverOpenedFD = 1 << 20
	if _, err := unix.FcntlInt(uintptr(neverOpenedFD), unix.F_GETFD, 0); err == nil {
		t.Fatalf("fd %d is unexpectedly open; pick a higher one", neverOpenedFD)
	}

	platform := &fdPlatform{
		recordingPlatform: recordingPlatform{
			lines:                 make(chan string, 256),
			underNetworkExtension: true,
		},
		fd: int32(neverOpenedFD),
	}
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	err = svc.Start(helloYAML)
	if err == nil || !strings.Contains(err.Error(), "dup tunnel fd") {
		t.Fatalf("Start should surface a closed tunnel fd, got %v", err)
	}
	if svc.running || svc.tunFd != -1 || svc.liveTunFd != -1 || svc.hasLiveTun {
		t.Fatalf("failed Start retained live state: running=%v tunFd=%d live=%d hasTun=%v",
			svc.running, svc.tunFd, svc.liveTunFd, svc.hasLiveTun)
	}
}

func TestCloseFDIfOpenIsIdempotent(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer unix.Close(fds[1])

	closeFDIfOpen(fds[0])
	closeFDIfOpen(fds[0])
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err == nil {
		t.Fatal("fd remained open")
	}
}

func (p *fdPlatform) OpenTun(options TunOptions) (int32, error) {
	p.openTunCall++
	if options != nil {
		p.gotMTU = options.GetMTU()
		it := options.GetInet4Address()
		if it.HasNext() {
			p.gotInet4 = it.Next().String()
		}
	}
	if p.openTunErr != nil {
		return -1, p.openTunErr
	}
	return p.fd, nil
}

func TestFinalizeConfigRunsBeforeOpenTun(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	cfg := &config.Config{
		General:    &config.General{Inbound: config.Inbound{Tun: LC.Tun{MTU: 1500}}},
		Controller: &config.Controller{},
	}
	finalizeConfigForIOS(cfg, true)
	platform := &fdPlatform{fd: int32(fds[0])}
	dupFd, err := prepareTunBridgeFD(platform, &cfg.General.Tun)
	if err != nil {
		t.Fatalf("prepareTunBridgeFD: %v", err)
	}
	defer unix.Close(dupFd)

	if platform.gotMTU != defaultTunMTU {
		t.Fatalf("OpenTun observed MTU %d, want normalized %d", platform.gotMTU, defaultTunMTU)
	}
	if !cfg.General.Tun.Enable {
		t.Fatal("NE local-proxy config was not forced to tun")
	}
}

func TestTunConfigurationsEqualChecksMoreThanFD(t *testing.T) {
	base := LC.Tun{
		Enable:         true,
		MTU:            uint32(defaultTunMTU),
		FileDescriptor: 42,
		Inet4Address:   []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
	}
	if !tunConfigurationsEqual(base, base) {
		t.Fatal("identical effective tun should be reloadable")
	}
	changed := base
	changed.StrictRoute = true
	if tunConfigurationsEqual(base, changed) {
		t.Fatal("same fd with changed tun options must require an appex restart")
	}
}

func TestTunConfigurationsEqualCoversUpstreamOmissions(t *testing.T) {
	base := LC.Tun{
		LoopbackAddress:     []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")},
		ExcludeSrcPort:      []uint16{443, 80},
		ExcludeSrcPortRange: []string{"1000:2000"},
		ExcludeDstPort:      []uint16{53},
		ExcludeDstPortRange: []string{"3000:4000"},
	}
	reordered := base
	reordered.LoopbackAddress = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}
	reordered.ExcludeSrcPort = []uint16{80, 443}
	if !tunConfigurationsEqual(base, reordered) {
		t.Fatal("ordering-only differences must remain reloadable")
	}

	for name, mutate := range map[string]func(*LC.Tun){
		"loopback address": func(tun *LC.Tun) { tun.LoopbackAddress[0] = netip.MustParseAddr("10.0.0.3") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTunSlices(base)
			mutate(&changed)
			if tunConfigurationsEqual(base, changed) {
				t.Fatal("changed tun field omitted from reload equality")
			}
		})
	}
}

func TestTunConfigurationsEqualIgnoresFieldsDarwinNeverReads(t *testing.T) {
	base := LC.Tun{Enable: true, MTU: uint32(defaultTunMTU), FileDescriptor: 42}
	for name, mutate := range map[string]func(*LC.Tun){
		"include-interface":      func(tun *LC.Tun) { tun.IncludeInterface = []string{"eth0"} },
		"exclude-interface":      func(tun *LC.Tun) { tun.ExcludeInterface = []string{"eth1"} },
		"include-uid":            func(tun *LC.Tun) { tun.IncludeUID = []uint32{501} },
		"include-uid-range":      func(tun *LC.Tun) { tun.IncludeUIDRange = []string{"1000:2000"} },
		"exclude-uid":            func(tun *LC.Tun) { tun.ExcludeUID = []uint32{0} },
		"exclude-uid-range":      func(tun *LC.Tun) { tun.ExcludeUIDRange = []string{"3000:4000"} },
		"exclude-src-port":       func(tun *LC.Tun) { tun.ExcludeSrcPort = []uint16{53} },
		"exclude-src-port-range": func(tun *LC.Tun) { tun.ExcludeSrcPortRange = []string{"1:2"} },
		"exclude-dst-port":       func(tun *LC.Tun) { tun.ExcludeDstPort = []uint16{443} },
		"exclude-dst-port-range": func(tun *LC.Tun) { tun.ExcludeDstPortRange = []string{"3:4"} },
		"include-mac-address":    func(tun *LC.Tun) { tun.IncludeMACAddress = []string{"00:11:22:33:44:55"} },
		"exclude-mac-address":    func(tun *LC.Tun) { tun.ExcludeMACAddress = []string{"66:77:88:99:aa:bb"} },
		"include-android-user":   func(tun *LC.Tun) { tun.IncludeAndroidUser = []int{0} },
		"include-package":        func(tun *LC.Tun) { tun.IncludePackage = []string{"a"} },
		"exclude-package":        func(tun *LC.Tun) { tun.ExcludePackage = []string{"b"} },
		"auto-redirect":          func(tun *LC.Tun) { tun.AutoRedirect = true },
		"auto-redirect marks": func(tun *LC.Tun) {
			tun.AutoRedirectInputMark, tun.AutoRedirectOutputMark = 1, 2
			tun.AutoRedirectIPRoute2FallbackRuleIndex = 3
		},
		"iproute2 indexes": func(tun *LC.Tun) { tun.IPRoute2TableIndex, tun.IPRoute2RuleIndex = 100, 200 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTunSlices(base)
			mutate(&changed)
			if !tunConfigurationsEqual(base, changed) {
				t.Fatal("a field nothing on Darwin reads made the reload demand an appex restart")
			}
		})
	}
}

func TestTunConfigurationsEqualDoesNotMutateInputs(t *testing.T) {
	left := LC.Tun{
		RouteAddress:    []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("10.0.0.0/8")},
		LoopbackAddress: []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")},
		ExcludeSrcPort:  []uint16{443, 80},
	}
	right := cloneTunSlices(left)
	if !tunConfigurationsEqual(left, right) {
		t.Fatal("identical tun configurations differ")
	}
	if got := left.RouteAddress[0].String(); got != "192.168.0.0/16" {
		t.Fatalf("route input mutated to %s", got)
	}
	if got := left.LoopbackAddress[0].String(); got != "10.0.0.2" {
		t.Fatalf("loopback input mutated to %s", got)
	}
	if got := left.ExcludeSrcPort[0]; got != 443 {
		t.Fatalf("port input mutated to %d", got)
	}
}

func TestPrepareTunBridgeFDDupsIndependently(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	readEnd, writeEnd := fds[0], fds[1]
	defer unix.Close(writeEnd)

	platform := &fdPlatform{fd: int32(readEnd)}
	tun := &LC.Tun{Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}

	dupFd, err := prepareTunBridgeFD(platform, tun)
	if err != nil {
		t.Fatalf("prepareTunBridgeFD: %v", err)
	}
	defer unix.Close(dupFd)

	if dupFd == readEnd {
		t.Fatal("dup must be a distinct fd from the platform's")
	}
	if platform.openTunCall != 1 {
		t.Fatalf("OpenTun called %d times, want 1", platform.openTunCall)
	}
	if platform.gotInet4 != "198.18.0.1/30" {
		t.Fatalf("OpenTun got TunOptions inet4 %q, want 198.18.0.1/30", platform.gotInet4)
	}

	if err := unix.Close(readEnd); err != nil {
		t.Fatalf("close original: %v", err)
	}
	if _, err := unix.Write(writeEnd, []byte("x")); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	buf := make([]byte, 1)
	n, err := unix.Read(dupFd, buf)
	if err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("dup fd not independent/alive after closing original: n=%d err=%v", n, err)
	}
}

func TestPrepareTunBridgeFDPropagatesOpenTunError(t *testing.T) {
	platform := &fdPlatform{fd: -1, openTunErr: errNotImplemented}
	_, err := prepareTunBridgeFD(platform, &LC.Tun{})
	if err == nil {
		t.Fatal("prepareTunBridgeFD must surface OpenTun failure")
	}
}
