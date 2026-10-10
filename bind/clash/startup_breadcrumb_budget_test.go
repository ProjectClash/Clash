package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

func setRuntimeSetupSoftMemoryLimitForTest(t *testing.T, limit int64) {
	t.Helper()
	setupMu.Lock()
	previous := currentRuntimeSetup.softMemoryLimit
	currentRuntimeSetup.softMemoryLimit = limit
	setupMu.Unlock()
	t.Cleanup(func() {
		setupMu.Lock()
		currentRuntimeSetup.softMemoryLimit = previous
		setupMu.Unlock()
	})
}

func TestNoBudgetIsAbsentFromTheRecordRatherThanZero(t *testing.T) {
	home := breadcrumbHome(t)
	setRuntimeSetupSoftMemoryLimitForTest(t, 0)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("apply:profile")

	explanation := ExplainLastStartup()
	if explanation == "" {
		t.Fatal("no record to read")
	}
	if strings.Contains(explanation, "budgetBytes") {
		t.Fatalf("a record with no budget still shipped a budgetBytes field, which reads as a measured ceiling: %s", explanation)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(explanation), &decoded); err != nil {
		t.Fatalf("explanation is not JSON: %v", err)
	}
	if _, present := decoded["budgetBytes"]; present {
		t.Fatal("budgetBytes is present, so a client can still do arithmetic with it")
	}
	if _, present := decoded["footprintBytes"]; !present {
		t.Fatal("dropping the budget also dropped the footprint, which is the half that is real")
	}
	_ = home
}

func TestARealBudgetStillTravels(t *testing.T) {
	breadcrumbHome(t)
	setRuntimeSetupSoftMemoryLimitForTest(t, 37<<20)
	setStartupBreadcrumbRecording(true)
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })

	recordStartupStage("apply:profile")

	explanation := ExplainLastStartup()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(explanation), &decoded); err != nil {
		t.Fatalf("explanation is not JSON: %v", err)
	}
	budget, present := decoded["budgetBytes"]
	if !present {
		t.Fatal("a record written under a real soft limit carried no budget")
	}
	if budget.(float64) != float64(37<<20) {
		t.Fatalf("budget travelled as %v, not the limit that was set", budget)
	}
}
