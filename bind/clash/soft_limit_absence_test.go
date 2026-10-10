package clash

import (
	"encoding/json"
	"testing"
)

func TestRuntimeDiagnosticsOmitsASoftLimitThatWasNeverSet(t *testing.T) {
	setRuntimeSetupSoftMemoryLimitForTest(t, 0)

	encoded := runtimeSetupDiagnosticsForTest(t)
	if _, present := encoded["softMemoryLimit"]; present {
		t.Fatalf("runtime diagnostics reported a soft limit that was never set: %v", encoded["softMemoryLimit"])
	}
}

func TestRuntimeDiagnosticsStillReportsALimitThatExists(t *testing.T) {
	setRuntimeSetupSoftMemoryLimitForTest(t, 37<<20)

	encoded := runtimeSetupDiagnosticsForTest(t)
	value, present := encoded["softMemoryLimit"]
	if !present {
		t.Fatal("a soft limit that was set did not reach the diagnostics")
	}
	if int64(value.(float64)) != int64(37<<20) {
		t.Fatalf("soft limit travelled as %v", value)
	}
}

func runtimeSetupDiagnosticsForTest(t *testing.T) map[string]any {
	t.Helper()
	service := &BoxService{tunFd: -1, liveTunFd: -1}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(service.RuntimeDiagnosticsJSON()), &decoded); err != nil {
		t.Fatalf("runtime diagnostics is not JSON: %v", err)
	}
	return decoded
}

func TestOOMEvidenceOmitsASoftLimitThatWasNeverSet(t *testing.T) {
	evidence := oomEvidence{PressureLevel: "critical"}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, present := decoded["softMemoryLimit"]; present {
		t.Fatalf("the evidence record carried a soft limit of zero: %s", encoded)
	}
}
