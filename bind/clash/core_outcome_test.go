package clash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func startedServiceForOutcome(t *testing.T) *BoxService {
	t.Helper()
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if outcome := svc.StartClassified(helloYAML); outcome.ErrorClass != "" {
		t.Fatalf("StartClassified: %s %s", outcome.ErrorClass, outcome.Message)
	}
	return svc
}

func TestReloadClassifiedNamesTheRunningState(t *testing.T) {
	svc := startedServiceForOutcome(t)

	if outcome := svc.ReloadClassified("mode: [broken"); outcome.ErrorClass != CoreOutcomeConfig || outcome.Message == "" {
		t.Fatalf("broken YAML: class %q message %q, want config with the core's sentence", outcome.ErrorClass, outcome.Message)
	}
	if outcome := svc.ReloadClassified(helloYAML + "\n"); outcome.ErrorClass != "" || outcome.Message != "" {
		t.Fatalf("valid reload: class %q message %q, want success", outcome.ErrorClass, outcome.Message)
	}

	fresh, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if outcome := fresh.ReloadClassified(helloYAML); outcome.ErrorClass != CoreOutcomeRestart {
		t.Fatalf("reload before start: class %q, want restart", outcome.ErrorClass)
	}
}

func TestReloadClassifiedMemoryRefusal(t *testing.T) {
	svc := startedServiceForOutcome(t)
	fakeReloadMemoryReaders(t, 0, 20*testMiB)
	previousMeaning := zeroHeadroomMeansExhausted
	zeroHeadroomMeansExhausted = true
	t.Cleanup(func() { zeroHeadroomMeansExhausted = previousMeaning })

	outcome := svc.ReloadClassified(helloYAML)
	if outcome.ErrorClass != CoreOutcomeMemory || !strings.Contains(outcome.Message, "reload refused (memory)") {
		t.Fatalf("class %q message %q, want memory", outcome.ErrorClass, outcome.Message)
	}
}

func TestReloadClassifiedPanicBeforeCommitKeepsTheRunningCore(t *testing.T) {
	svc := startedServiceForOutcome(t)
	reloadTestPanicBeforeCommit.Store(true)
	t.Cleanup(func() { reloadTestPanicBeforeCommit.Store(false) })

	outcome := svc.ReloadClassified(helloYAML)
	if outcome.ErrorClass != CoreOutcomeConfig || !strings.Contains(outcome.Message, "panicked") {
		t.Fatalf("class %q message %q, want config naming the panic", outcome.ErrorClass, outcome.Message)
	}
	reloadTestPanicBeforeCommit.Store(false)
	if outcome := svc.ReloadClassified(helloYAML); outcome.ErrorClass != "" {
		t.Fatalf("the running core must still take a reload after a refused one: %q %q", outcome.ErrorClass, outcome.Message)
	}
}

func TestStartClassifiedConfigRefusal(t *testing.T) {
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	svc, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if outcome := svc.StartClassified("mode: [broken"); outcome.ErrorClass != CoreOutcomeConfig {
		t.Fatalf("class %q message %q, want config", outcome.ErrorClass, outcome.Message)
	}
	if outcome := svc.StartClassified(helloYAML); outcome.ErrorClass != "" {
		t.Fatalf("start after a config refusal: %q %q", outcome.ErrorClass, outcome.Message)
	}
}

func TestUnclassifiedReloadKeepsItsBehaviour(t *testing.T) {
	svc := startedServiceForOutcome(t)
	if err := svc.Reload("mode: [broken"); err == nil {
		t.Fatal("Reload must still reject broken YAML")
	}
	if err := svc.Reload(helloYAML + "\n"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
}

func TestCoreOutcomeClassesAreTheWireSpellings(t *testing.T) {
	for class, wire := range map[string]string{
		CoreOutcomeConfig: "config", CoreOutcomeMemory: "memory", CoreOutcomeRestart: "restart",
		CoreOutcomeCommitted: "committed", CoreOutcomeUnknown: "unknown",
	} {
		if class != wire {
			t.Errorf("class %q must be spelled %q on the wire", class, wire)
		}
	}
}

func TestStagingFailuresAreClassifiedByWhoseFaultTheyAre(t *testing.T) {
	classOf := func(err error) string { return coreOutcomeOf(err).ErrorClass }

	home := compileStagingHome(t)
	outside := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(outside, []byte("payload:\n  - DOMAIN,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := stagingRawWithProviderPath(t, "rule", outside)
	_, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if got := classOf(classify(CoreOutcomeUnknown, err)); err == nil || got != CoreOutcomeConfig {
		t.Fatalf("a provider path outside the container is the document's fault: class %q, err %v", got, err)
	}

	if err := os.Symlink(t.TempDir(), filepath.Join(home, providerRuntimeDirectoryName)); err != nil {
		t.Fatal(err)
	}
	source := writeRuleSource(t, "rules.yaml", "payload:\n  - DOMAIN,example.com\n")
	_, err = stageProviderRuntime(stagingRawWithProviderPath(t, "rule", source), runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if got := classOf(classify(CoreOutcomeUnknown, err)); err == nil || got != CoreOutcomeUnknown {
		t.Fatalf("a runtime directory the file system will not give us is not the document's fault: class %q, err %v", got, err)
	}
}
