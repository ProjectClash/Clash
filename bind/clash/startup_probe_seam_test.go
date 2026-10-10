package clash

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/hub/executor"
)

func armedProbeBreadcrumb(t *testing.T) string {
	t.Helper()
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	t.Cleanup(armStartupProbes())
	return filepath.Join(home, breadcrumbFileName)
}

func TestApplyStepsReachTheBreadcrumbAndNotOnlyThePhaseLog(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	executor.StartupProbe("profile")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("an apply step left no breadcrumb for the next launch to read: %v", err)
	}
	if record.Stage != "apply:profile" {
		t.Fatalf("breadcrumb stage is %q, so the client's apply:profile branch is unreachable in the field", record.Stage)
	}
}

func TestParseSectionsReachTheBreadcrumbToo(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	config.StartupProbe("dns")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("a parse section left no breadcrumb: %v", err)
	}
	if record.Stage != "parse:dns" {
		t.Fatalf("breadcrumb stage is %q, so the client's parse:dns branch is unreachable in the field", record.Stage)
	}
}

func TestTheProviderBeingBuiltIsNamedBeforeItIsBuilt(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	executor.StartupProbe("rule-provider-begin:reject")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("the provider about to be built left no breadcrumb: %v", err)
	}
	if record.Resource != "rule-provider:reject" {
		t.Fatalf("breadcrumb resource is %q; a kill inside Initial would not name the provider", record.Resource)
	}
	if record.Stage != "apply:rule-provider-begin:reject" {
		t.Fatalf("breadcrumb stage is %q", record.Stage)
	}
}

func BenchmarkAnApplyStepThroughTheBreadcrumb(b *testing.B) {
	home := b.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	b.Cleanup(func() { breadcrumbDirectory = previous })
	setStartupBreadcrumbRecording(true)
	b.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	for i := 0; i < b.N; i++ {
		recordStartupStage("apply:profile")
	}
}

func TestDisarmingStopsTheProbesFromWritingAnything(t *testing.T) {
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	disarm := armStartupProbes()
	disarm()

	if config.StartupProbe != nil || executor.StartupProbe != nil {
		t.Fatal("a disarmed Start left its probes installed for the next caller")
	}
	if _, err := readBreadcrumb(filepath.Join(home, breadcrumbFileName)); err == nil {
		t.Fatal("arming and disarming with no steps in between still wrote a record")
	}
}

func TestTheNodeListBeingBuiltIsNamedWithItsSizeBeforeItIsBuilt(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	config.StartupProbe("proxies-begin:7037")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatalf("the node list about to be built left no breadcrumb: %v", err)
	}
	if record.Stage != "parse:proxies-begin" {
		t.Fatalf("breadcrumb stage is %q, want parse:proxies-begin: the count is not part of the step's name", record.Stage)
	}
	if record.Count != 7037 {
		t.Fatalf("breadcrumb count is %d, want 7037", record.Count)
	}
	if record.Resource != "" {
		t.Fatalf("breadcrumb resource is %q: a node count is not something the reader named, and the client prints resources verbatim", record.Resource)
	}
}

func TestACountIsNotCarriedIntoTheNextStep(t *testing.T) {
	path := armedProbeBreadcrumb(t)

	config.StartupProbe("proxies-begin:7037")
	config.StartupProbe("proxies")

	record, err := readBreadcrumb(path)
	if err != nil {
		t.Fatal(err)
	}
	if record.Stage != "parse:proxies" || record.Count != 0 {
		t.Fatalf("breadcrumb is stage=%q count=%d after the node list was built, want parse:proxies with no count", record.Stage, record.Count)
	}
}

func TestAStartAnnouncesTheDecodeBeforeItsFirstDecodeOfTheText(t *testing.T) {
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(false)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	service, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	undecodable := "proxies: [\n"
	if err := service.Start(undecodable); err == nil {
		t.Fatal("the fixture was meant to stop the start inside the decode")
	}

	record, err := readBreadcrumb(filepath.Join(home, breadcrumbFileName))
	if err != nil {
		t.Fatalf("a start that stopped inside the decode left no breadcrumb: %v", err)
	}
	if record.Stage != "bind:unmarshal-begin" || record.Count != int64(len(undecodable)) {
		t.Fatalf("breadcrumb is stage=%q count=%d, want bind:unmarshal-begin with the %d bytes being decoded", record.Stage, record.Count, len(undecodable))
	}
}

func TestAStartAnnouncesTheNodeListBeforeBuildingIt(t *testing.T) {
	home := breadcrumbHome(t)
	setStartupBreadcrumbRecording(false)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	service, err := NewService(platform)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	unbuildable := `
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
  - {name: b, type: ss, server: 127.0.0.1, port: 2, cipher: no-such-cipher, password: x}
`
	if err := service.Start(unbuildable); err == nil {
		t.Fatal("the fixture was meant to stop the start while the node list is built")
	}

	record, err := readBreadcrumb(filepath.Join(home, breadcrumbFileName))
	if err != nil {
		t.Fatalf("a start that stopped building the node list left no breadcrumb: %v", err)
	}
	if record.Stage != "parse:proxies-begin" || record.Count != 2 {
		t.Fatalf("breadcrumb is stage=%q count=%d (failure %q), want parse:proxies-begin with 2 nodes", record.Stage, record.Count, record.FailureReason)
	}
}

func TestACountDoesNotChangeTheNameTheClientReadsFromThePhaseLog(t *testing.T) {
	armedProbeBreadcrumb(t)

	config.StartupProbe("proxies-begin:7037")

	lines := strings.Split(strings.TrimSpace(StartupPhaseTrace()), "\n")
	line := lines[len(lines)-1]
	_, afterMarker, found := strings.Cut(line, "go-phase=")
	name, afterName, hasFootprint := strings.Cut(afterMarker, "fp=")
	if !found || !hasFootprint {
		t.Fatalf("not a phase line: %q", line)
	}
	if got := strings.TrimSpace(name); got != "parse:proxies-begin" {
		t.Fatalf("the client reads the stage as %q, want parse:proxies-begin (line %q)", got, line)
	}
	if !strings.Contains(afterName, " count=7037") {
		t.Fatalf("the count is not on the line after fp=: %q", line)
	}
}
