package clash

import (
	"encoding/json"
	"testing"
)

func unifiedDelayRowFor(t *testing.T, yaml string) map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(yaml, RuntimeProfileMacOSPacketTunnel)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON: %v", err)
	}
	var report struct {
		Deviations []map[string]any `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatal(err)
	}
	for _, d := range report.Deviations {
		if d["field"] == "unified-delay" {
			return d
		}
	}
	return nil
}

func TestAWrittenUnifiedDelayIsNotReported(t *testing.T) {
	for _, written := range []string{"false", "true"} {
		yaml := "unified-delay: " + written + "\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
		if row := unifiedDelayRowFor(t, yaml); row != nil {
			t.Errorf("unified-delay: %s written, yet reported as a deviation: %v", written, row)
		}
	}
}

func TestAnUnwrittenUnifiedDelayIsReportedAsADefault(t *testing.T) {
	row := unifiedDelayRowFor(t, "proxies: []\nrules:\n  - MATCH,DIRECT\n")
	if row == nil {
		t.Fatal("unified-delay not written and not reported; the changed default is exactly the case to report")
	}
	if given, _ := row["given"].(string); given != "not set (core default: false)" {
		t.Fatalf("given = %q; for an unwritten field it names the upstream default", given)
	}
}
