package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinalizeWithOptionsAtAPathAnswersAsFromTheText(t *testing.T) {
	setupForMatch(t)
	reader := "mode: rule\nproxies:\n  - {type: direct, name: P}\nproxy-groups:\n  - {proxies: [P, DIRECT], type: select, name: G}\nrules:\n  - DOMAIN,a.example,P\n  - UID,501,G\n  - MATCH,G\n"
	sorted := "mode: rule\nproxies:\n  - {name: P, type: direct}\nproxy-groups:\n  - {name: G, proxies: [P, DIRECT], type: select}\nrules:\n  - DOMAIN,a.example,P\n  - UID,501,G\n  - MATCH,G\n"
	dir := t.TempDir()
	mergedPath, referencePath := filepath.Join(dir, "merged.yaml"), filepath.Join(dir, "reference.yaml")
	if err := os.WriteFile(mergedPath, []byte(sorted), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(referencePath, []byte(reader), 0o600); err != nil {
		t.Fatal(err)
	}
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": dir, "nodeLibraryDirectory": dir})
	options := func(reference map[string]any) string {
		o := map[string]any{"targetProfile": RuntimeProfileIOSPacketTunnel, "plan": true, "intent": true, "geodataMode": true, "geoCategories": true, "topLevelKeys": []string{"mode"}}
		for k, v := range reference {
			o[k] = v
		}
		b, _ := json.Marshal(o)
		return string(b)
	}
	fromText, err := FinalizeForIOSWithOptions(sorted, string(resources), options(map[string]any{"orderReference": reader}))
	if err != nil {
		t.Fatal(err)
	}
	atPath, err := FinalizeForIOSWithOptionsAtPath(mergedPath, string(resources), options(map[string]any{"orderReferencePath": referencePath}))
	if err != nil {
		t.Fatal(err)
	}
	if fromText.Value != atPath.Value {
		t.Fatalf("from the text:\n%s\nat the path:\n%s", fromText.Value, atPath.Value)
	}
	var answer struct{ Text string }
	if err := json.Unmarshal([]byte(atPath.Value), &answer); err != nil || !strings.Contains(answer.Text, "x-clash-rule-index") || !strings.Contains(answer.Text, "uid-removed") {
		t.Fatalf("not published to an index: %v\n%s", err, answer.Text)
	}
	group := answer.Text[strings.Index(answer.Text, "proxy-groups:"):]
	if p, ty, n := strings.Index(group, "proxies:"), strings.Index(group, "type: select"), strings.Index(group, "name: G"); !(p >= 0 && p < ty && ty < n) {
		t.Errorf("the reader's key order was not restored:\n%s", answer.Text)
	}
	if _, err := FinalizeForIOSWithOptionsAtPath(filepath.Join(dir, "missing.yaml"), string(resources), options(nil)); err == nil {
		t.Error("a missing file published")
	}
}
