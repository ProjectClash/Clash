package clash

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestZeroByteRuleProviderFileStartsWarnAndContinue(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, behavior, format string }{
		{"mrs", "ipcidr", "mrs"},
		{"classical", "classical", "yaml"},
	} {
		payload := filepath.Join(options.WorkingPath, "empty-"+tc.name+"."+tc.format)
		if err := os.WriteFile(payload, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
rule-providers:
  gone:
    type: file
    behavior: %s
    format: %s
    path: %q
rules:
  - RULE-SET,gone,DIRECT
  - MATCH,DIRECT
`, tc.behavior, tc.format, payload)
		service, err := NewService(newRecordingPlatform())
		if err != nil {
			t.Fatal(err)
		}
		startErr := service.Start(content)
		_ = service.Close()
		if startErr != nil {
			t.Fatalf("%s: a zero-byte rule provider must warn and continue, got: %v", tc.name, startErr)
		}
	}
}
