package clash

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var outcomePhases = map[string]string{
	"config-parsed": "config-refused",
}

func TestEveryOutcomePhaseHasAFailingCounterpart(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("cannot read service.go: %v", err)
	}
	body := string(source)

	emitted := map[string]bool{}
	for _, match := range regexp.MustCompile(`startupPhase\("([^"]+)"\)`).FindAllStringSubmatch(body, -1) {
		emitted[match[1]] = true
	}
	if len(emitted) == 0 {
		t.Fatal("found no startupPhase calls; the scan is broken, not the code")
	}

	for outcome, counterpart := range outcomePhases {
		if !emitted[outcome] {
			t.Errorf("phase %q is declared here as outcome-shaped but service.go no longer emits it; "+
				"drop the entry or rename it with its counterpart", outcome)
			continue
		}
		if !emitted[counterpart] {
			t.Errorf("phase %q says an outcome was reached, and nothing marks the other outcome. A record "+
				"ending at %q then reads as success to whoever finds it -- which is how a device round was "+
				"attributed wrongly. Emit %q where the failure is known.", outcome, outcome, counterpart)
		}
	}

	for outcome, counterpart := range outcomePhases {
		lines := strings.Split(body, "\n")
		for index, line := range lines {
			if !strings.Contains(line, `startupPhase("`+counterpart+`")`) {
				continue
			}
			guarded := false
			for back := index - 1; back >= 0; back-- {
				text := strings.TrimSpace(lines[back])
				if text == "" || strings.HasPrefix(text, "//") {
					continue
				}
				guarded = strings.Contains(text, "if err != nil")
				break
			}
			if !guarded {
				t.Errorf("service.go:%d emits %q outside a failure branch; it must mark the ending %q does "+
					"not, or the record is ambiguous again", index+1, counterpart, outcome)
			}
		}
	}
}

func TestARefusalReachesThePhaseLog(t *testing.T) {
	setupConfigPipelineTest(t)
	phaseLog := filepath.Join(t.TempDir(), "phases.log")
	previous := startupPhaseLogPath()
	configureStartupPhaseLogPath(phaseLog)
	t.Cleanup(func() { configureStartupPhaseLogPath(previous) })

	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer func() { _ = service.Close() }()

	if err := service.Start("proxies:\n  - {name: [unclosed\n"); err == nil {
		t.Fatal("Start accepted a document that is not yaml")
	}

	body, err := os.ReadFile(phaseLog)
	if err != nil {
		t.Fatalf("the phase log was never written: %v", err)
	}
	record := string(body)
	if !strings.Contains(record, "config-parsed") {
		t.Fatalf("no phase reached the log, so this test measures nothing:\n%s", record)
	}
	if !strings.Contains(record, "config-refused") {
		t.Fatalf("a refused configuration left config-parsed in the record and nothing else, which is "+
			"exactly the reading that cost two lanes a night:\n%s", record)
	}
}
