package clash

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

var proxyImportPseudoOutbounds = map[string]struct{}{
	"direct": {}, "dns": {}, "reject": {}, "rematch": {},
}

var kernelOutboundCasePattern = regexp.MustCompile(`(?m)^\tcase "([a-z0-9-]+)":`)

func kernelOutboundTypes(t *testing.T) []string {
	t.Helper()
	source, err := os.ReadFile("../../adapter/parser.go")
	if err != nil {
		t.Fatalf("read the kernel's outbound parser: %v", err)
	}
	matches := kernelOutboundCasePattern.FindAllSubmatch(source, -1)
	types := make([]string, 0, len(matches))
	for _, match := range matches {
		name := string(match[1])
		if _, pseudo := proxyImportPseudoOutbounds[name]; pseudo {
			continue
		}
		types = append(types, name)
	}
	if len(types) < 15 {
		t.Fatalf("extracted only %d outbound types from the kernel's parser -- the pattern no longer matches its switch", len(types))
	}
	return types
}

func TestEveryKernelOutboundImportsTheSameFromEitherContainer(t *testing.T) {
	read := func(t *testing.T, payload []byte, label string) string {
		t.Helper()
		box, err := InspectProxyPayloadForIOS(payload, "nodeBundle")
		if err != nil {
			return "error: " + err.Error()
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("%s report: %v", label, err)
		}
		encoded, err := json.Marshal(map[string]any{
			"proxies":     report.Proxies,
			"rejected":    report.Skipped,
			"unsupported": report.Skipped,
		})
		if err != nil {
			t.Fatalf("%s: marshal report: %v", label, err)
		}
		return string(encoded)
	}

	for _, proxyType := range kernelOutboundTypes(t) {
		t.Run(proxyType, func(t *testing.T) {
			object := map[string]any{
				"name": "n", "type": proxyType, "server": "h.example", "port": 443,
			}
			bare, err := json.Marshal([]any{object})
			if err != nil {
				t.Fatalf("marshal bare array: %v", err)
			}
			keyed, err := json.Marshal(map[string]any{"proxies": []any{object}})
			if err != nil {
				t.Fatalf("marshal keyed document: %v", err)
			}
			bareResult := read(t, bare, "bare array")
			keyedResult := read(t, keyed, `{"proxies": [...]}`)
			if bareResult != keyedResult {
				t.Errorf("container spelling changed the import of a %s proxy\n  bare: %s\n keyed: %s",
					proxyType, bareResult, keyedResult)
			}
		})
	}
}
