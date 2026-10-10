package clash

import (
	"encoding/json"
	"testing"
)

func storeFakeIPRowFor(t *testing.T, yaml string) map[string]any {
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
		if d["field"] == "profile.store-fake-ip" {
			return d
		}
	}
	return nil
}

func TestAWrittenDefaultOnlyFieldIsNotReported(t *testing.T) {
	for _, written := range []string{"false", "true"} {
		yaml := "profile:\n  store-fake-ip: " + written + "\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
		if row := storeFakeIPRowFor(t, yaml); row != nil {
			t.Errorf("store-fake-ip: %s written explicitly, yet reported as a deviation: %v\n"+
				"applyAppleDefaults leaves an explicit value alone, so nothing happened", written, row)
		}
	}
}

func TestAnUnwrittenDefaultOnlyFieldIsReportedAsADefault(t *testing.T) {
	row := storeFakeIPRowFor(t, "proxies: []\nrules:\n  - MATCH,DIRECT\n")
	if row == nil {
		t.Fatal("store-fake-ip not written and not reported; the changed default is exactly the case to report")
	}
	if given, _ := row["given"].(string); given != "not set (core default: false)" {
		t.Fatalf("given = %q; for an unwritten field it names the upstream default", given)
	}
}

func TestDefaultOnlyIsOnlyOnRecoverableForcedRules(t *testing.T) {
	count := 0
	for _, rule := range deviationRules {
		if !rule.defaultOnly {
			continue
		}
		count++
		if rule.category != deviationForced || !rule.recoverable {
			t.Errorf("%s: defaultOnly on a %s rule with recoverable=%v; the bit means "+
				"\"forces a default, honours a written value\"", rule.field, rule.category, rule.recoverable)
		}
		if rule.upstreamDefault == "" {
			t.Errorf("%s: defaultOnly without upstreamDefault; the unwritten row has no baseline to name", rule.field)
		}
	}
	if count == 0 {
		t.Fatal("no rule is defaultOnly; store-fake-ip was, and a test over none proves nothing")
	}
}
