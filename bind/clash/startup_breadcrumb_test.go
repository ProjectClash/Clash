package clash

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata"
	C "github.com/ProjectClash/Clash/constant"
)

func breadcrumbHome(t *testing.T) string {
	t.Helper()
	options := testOptions(t)
	options.MemoryLimit = 50 << 20
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	previousRecording := breadcrumbRecording.Load()
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() {
		breadcrumbDirectory = previous
		setStartupBreadcrumbRecording(previousRecording)
	})
	return home
}

func TestBreadcrumbSurvivesAProcessThatNeverStopped(t *testing.T) {
	home := breadcrumbHome(t)

	recordStartupStage("parse")
	recordStartupStage("geosite:cn")

	explanation := ExplainLastStartup()
	if explanation == "" {
		t.Fatal("a tunnel that died mid-startup left nothing to explain")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(explanation), &report); err != nil {
		t.Fatalf("explanation is not JSON: %s", explanation)
	}
	if report["completed"] != false {
		t.Fatalf("a tunnel killed mid-startup was reported as completed: %v", report)
	}
	if report["stage"] != "geosite:cn" {
		t.Fatalf("the last stage reached was %v, not the one it died in", report["stage"])
	}
	if _, err := os.Stat(filepath.Join(home, breadcrumbFileName)); err != nil {
		t.Fatalf("breadcrumb is not on disk, so it could not survive a kill: %v", err)
	}
}

func TestBreadcrumbIsClearedByAStartThatSucceeds(t *testing.T) {
	breadcrumbHome(t)

	recordStartupStage("parse")
	recordStartupComplete()

	explanation := ExplainLastStartup()
	if explanation != "" {
		t.Fatalf("a clean start left an explanation behind: %s", explanation)
	}
}

func TestBreadcrumbCarriesTheFootprintAndTheBudget(t *testing.T) {
	breadcrumbHome(t)

	recordStartupStage("geoip:us")

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	footprint, _ := report["footprintBytes"].(float64)
	if footprint <= 0 {
		t.Fatalf("no footprint recorded: %v", report)
	}
	budget, _ := report["budgetBytes"].(float64)
	if budget <= 0 {
		t.Fatalf("no budget recorded, so the footprint has nothing to be judged against: %v", report)
	}
}

func TestExplainLastStartupIsEmptyWhenNothingHappened(t *testing.T) {
	breadcrumbHome(t)
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("invented an explanation with no breadcrumb: %s", explanation)
	}
}

func TestBreadcrumbDistinguishesRunningFromDead(t *testing.T) {
	breadcrumbHome(t)
	recordStartupStage("parse")

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	if _, ok := report["startedAt"]; !ok {
		t.Fatalf("no start time, so a live run cannot be told from a dead one: %v", report)
	}
}

func TestParsingUnderTheTunnelRecordsWhereItGotTo(t *testing.T) {
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	options.MemoryLimit = 50 << 20
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	previousDir := breadcrumbDirectory
	breadcrumbDirectory = options.WorkingPath
	t.Cleanup(func() {
		breadcrumbDirectory = previousDir
		setStartupBreadcrumbRecording(false)
	})

	config := `mode: rule
proxies: []
dns:
  enable: true
  nameserver:
    - 223.5.5.5
rules:
  - MATCH,DIRECT
`
	if _, runtime, err := parseConfigForIOSRuntime(config, true, "breadcrumb-test"); err != nil {
		t.Logf("parse stopped with: %v (a failure is still a recorded stage)", err)
	} else if runtime != nil {
		runtime.close()
	}

	explanation := ExplainLastStartup()
	if explanation == "" {
		t.Fatal("a tunnel parse recorded nothing: the reporter is not wired, and a kill " +
			"during this parse would leave the reader with the system sentence and no more")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(explanation), &report); err != nil {
		t.Fatal(err)
	}
	if stage, _ := report["stage"].(string); !strings.HasPrefix(stage, "bind:") {
		t.Fatalf("the record does not name a startup stage: %q", stage)
	}
	if footprint, _ := report["footprintBytes"].(float64); footprint <= 0 {
		t.Fatalf("no footprint, so the record cannot say whether memory was the reason: %v", report)
	}
	if budget, _ := report["budgetBytes"].(float64); budget <= 0 {
		t.Fatalf("no budget, so the footprint has nothing to be judged against: %v", report)
	}
}

func TestBuildingAGeoResourceRecordsWhichOne(t *testing.T) {
	breadcrumbHome(t)
	previous := progressReporterInstalled()
	restoreProgressReporter(recordStartupStage)
	t.Cleanup(func() { restoreProgressReporter(previous) })

	_, _ = geodata.LoadGeoIPMatcher("zz")

	if explanation := ExplainLastStartup(); !strings.Contains(explanation, "geoip:zz") {
		t.Fatalf("building a matcher recorded nothing about which one: %s", explanation)
	}
}

func TestAStepThatIsNotAboutAResourceClearsIt(t *testing.T) {
	breadcrumbHome(t)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupResource("geosite:cn")
	recordStartupStage("bind:providers-staged")

	var report map[string]any
	if err := json.Unmarshal([]byte(ExplainLastStartup()), &report); err != nil {
		t.Fatal(err)
	}
	if report["resource"] != "" && report["resource"] != nil {
		t.Fatalf("a later step still carries the previous resource, so the client would "+
			"say the tunnel died loading something it had already finished: %v", report)
	}
	if report["stage"] != "bind:providers-staged" {
		t.Fatalf("the internal stage was lost: %v", report)
	}
}

func TestTheSeamDoesNotFireOnEveryMatch(t *testing.T) {
	home := breadcrumbHome(t)
	previous := progressReporterInstalled()
	fired := 0
	restoreProgressReporter(func(resource string) {
		fired++
		recordStartupResource(resource)
	})
	t.Cleanup(func() { restoreProgressReporter(previous) })

	geodata.ClearGeoIPCache()
	for i := 0; i < 5; i++ {
		_, _ = geodata.LoadGeoIPMatcher("cn")
	}
	if fired > 1 {
		t.Fatalf("the seam fired %d times for %d loads of one country: it sits outside the "+
			"singleflight, so it runs on every rule match rather than once per build", fired, 5)
	}
	_ = home
}

func TestASuccessfulStartLeavesNoDeathReport(t *testing.T) {
	breadcrumbHome(t)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("bind:unmarshalled")
	recordStartupResource("geosite:cn")
	markStartupComplete()

	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("a completed start still reports a death: %s", explanation)
	}
}

func TestARecordFromAnotherInstallIsNotExplained(t *testing.T) {
	home := breadcrumbHome(t)

	recordStartupStage("bind:normalized")
	if ExplainLastStartup() == "" {
		t.Fatal("this install's own record was not returned")
	}

	path := filepath.Join(home, breadcrumbFileName)
	var stored map[string]any
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["install"] == nil || stored["install"] == "" {
		t.Fatal("the record carries no install identity, so nothing can tell installs apart")
	}
	stored["install"] = "some-other-install"
	rewritten, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}

	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("explained a record another install wrote: %s", explanation)
	}
}

func TestALegacyRecordWithoutAnInstallIsNotExplained(t *testing.T) {
	home := breadcrumbHome(t)
	legacy := `{"stage":"bind:normalized","resource":"","completed":false,` +
		`"footprintBytes":1,"budgetBytes":2,"startedAt":"x","updatedAt":"x"}`
	if err := os.WriteFile(filepath.Join(home, breadcrumbFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("explained a record written before installs were identified: %s", explanation)
	}
}

func TestTheInstallIdentityIsNotAPath(t *testing.T) {
	identity := currentInstallIdentity()
	if identity == "" {
		t.Fatal("no install identity")
	}
	if strings.ContainsAny(identity, `/\`) || strings.Contains(identity, "..") {
		t.Fatalf("the install identity looks like a path: %q", identity)
	}
	if identity != currentInstallIdentity() {
		t.Fatal("the install identity changed between calls, so every launch would look like a reinstall")
	}
}

func TestCriticalPressureRefreshesTheRecordFootprint(t *testing.T) {
	breadcrumbHome(t)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("bind:providers-staged")
	path := breadcrumbPath()
	stale, err := readBreadcrumb(path)
	if err != nil {
		t.Fatal(err)
	}
	stale.FootprintBytes = 1
	writeBreadcrumb(path, stale)

	refreshStartupBreadcrumbFootprint()

	refreshed, err := readBreadcrumb(path)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.FootprintBytes <= 1 {
		t.Fatal("critical pressure did not refresh the record's footprint")
	}
	if refreshed.Stage != "bind:providers-staged" {
		t.Fatalf("the refresh lost the stage: %q", refreshed.Stage)
	}

	markStartupComplete()
	refreshStartupBreadcrumbFootprint()
	if explanation := ExplainLastStartup(); explanation != "" {
		t.Fatalf("pressure after a completed start resurrected a record: %s", explanation)
	}
}

func TestAFailingStartLeavesItsReasonInTheBreadcrumb(t *testing.T) {
	home := t.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	t.Cleanup(func() { breadcrumbDirectory = previous })
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("bind:test-stage")
	recordStartupFailure(errAsIfFromStart("decode geodata file: list https not found"))

	explained := ExplainLastStartup()
	if explained == "" {
		t.Fatal("a failed start explains nothing")
	}
	var record struct {
		Completed     bool   `json:"completed"`
		FailureReason string `json:"failureReason"`
		Stage         string `json:"stage"`
	}
	if err := json.Unmarshal([]byte(explained), &record); err != nil {
		t.Fatalf("explanation does not decode: %v", err)
	}
	if record.Completed {
		t.Fatal("a failed start must not read as completed")
	}
	if !strings.Contains(record.FailureReason, "list https not found") {
		t.Fatalf("the reason did not survive: %q", record.FailureReason)
	}
	if record.Stage != "bind:test-stage" {
		t.Fatalf("the failure must keep the stage it happened in, got %q", record.Stage)
	}
}

func TestStartWiresTheFailureIntoTheBreadcrumb(t *testing.T) {
	home := t.TempDir()
	previous := breadcrumbDirectory
	breadcrumbDirectory = home
	t.Cleanup(func() { breadcrumbDirectory = previous })
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	service, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	startErr := service.Start("proxies:\n  - {name: A, type: not-a-real-protocol, server: e.test, port: 1}\n")
	if startErr == nil {
		t.Fatal("a config the kernel refuses must fail Start")
	}
	explained := ExplainLastStartup()
	if explained == "" {
		t.Fatal("the failing Start left no explanation")
	}
	var record struct {
		FailureReason string `json:"failureReason"`
	}
	if err := json.Unmarshal([]byte(explained), &record); err != nil {
		t.Fatalf("explanation does not decode: %v", err)
	}
	if record.FailureReason == "" {
		t.Fatal("the failing Start left an empty reason")
	}
	if !strings.Contains(startErr.Error(), record.FailureReason) &&
		!strings.Contains(record.FailureReason, "not-a-real-protocol") {
		t.Fatalf("the recorded reason %q does not correspond to the returned error %q",
			record.FailureReason, startErr)
	}
}

func errAsIfFromStart(text string) error { return errors.New(text) }
