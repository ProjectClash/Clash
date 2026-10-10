package clash

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func decodeAnswer(t *testing.T, box *StringBox, err error, into any) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(box.Value))
	decoder.UseNumber()
	if err := decoder.Decode(into); err != nil {
		t.Fatalf("%v: %s", err, box.Value)
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func wantDocument(text string) (json.RawMessage, string) {
	box, err := YamlToJSON(text)
	if err != nil {
		return nil, err.Error()
	}
	return json.RawMessage(box.Value), ""
}

type yamlToJSONAnswerForTest struct {
	Document      json.RawMessage `json:"document"`
	DocumentError string          `json:"documentError"`
	ShapeError    string          `json:"shapeError"`
}

type editAnswerForTest struct {
	OK            bool            `json:"ok"`
	Text          string          `json:"text"`
	Code          string          `json:"code"`
	Message       string          `json:"message"`
	Document      json.RawMessage `json:"document"`
	DocumentError string          `json:"documentError"`
	ShapeError    string          `json:"shapeError"`
}

type finalizeAnswerForTest struct {
	Text        string                     `json:"text"`
	Plan        json.RawMessage            `json:"plan"`
	PlanError   string                     `json:"planError"`
	Intent      json.RawMessage            `json:"intent"`
	IntentError string                     `json:"intentError"`
	GeodataMode *bool                      `json:"geodataMode"`
	TopLevel    map[string]json.RawMessage `json:"topLevel"`
}

func TestFinalizeForIOSWithOptionsRestoresTheReferenceOrder(t *testing.T) {
	setupConfigPipelineTest(t)
	reader := "mode: rule\ndns:\n  enable: true\n  nameserver-policy:\n    '+.google.com': 8.8.8.8\n    '+.com': 1.1.1.1\nrules:\n  - MATCH,DIRECT\n"
	sorted := "dns:\n  enable: true\n  nameserver-policy:\n    '+.com': 1.1.1.1\n    '+.google.com': 8.8.8.8\nmode: rule\nrules:\n  - MATCH,DIRECT\n"
	var withReference, without finalizeAnswerForTest
	box, err := FinalizeForIOSWithOptions(sorted, "", mustJSON(map[string]string{"orderReference": reader}))
	decodeAnswer(t, box, err, &withReference)
	box, err = FinalizeForIOSWithOptions(sorted, "", "")
	decodeAnswer(t, box, err, &without)
	google, com := strings.Index(withReference.Text, "+.google.com:"), strings.Index(withReference.Text, "+.com:")
	if !strings.HasPrefix(withReference.Text, "mode: rule\ndns:\n") || google < 0 || com < 0 || google > com {
		t.Errorf("the reader's order was not restored:\n%s", withReference.Text)
	}
	old, err := FinalizeForIOS(sorted, "")
	if err != nil || without.Text != old.Value {
		t.Errorf("without the reference the text is FinalizeForIOS's: %v\n%s", err, without.Text)
	}
	google, com = strings.Index(without.Text, "+.google.com:"), strings.Index(without.Text, "+.com:")
	if google < 0 || com < 0 || google < com {
		t.Errorf("without the reference the merged text's (sorted) order stands:\n%s", without.Text)
	}
}

func savePathBenchConfig() string {
	var text strings.Builder
	text.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nproxies:\n")
	for i := range 10000 {
		fmt.Fprintf(&text, "  - {name: node-%05d, type: ss, server: 192.0.2.%d, port: %d, cipher: aes-128-gcm, password: p%05d, udp: true}\n", i, i%250+1, 10000+i, i)
	}
	text.WriteString("proxy-groups:\n  - name: Proxy\n    type: select\n    proxies: [node-00000, node-00001, DIRECT]\nrules:\n")
	for i := range 10000 {
		fmt.Fprintf(&text, "  - DOMAIN-SUFFIX,site-%05d.example,Proxy\n", i)
	}
	text.WriteString("  - MATCH,DIRECT\n")
	return text.String()
}

func setupSavePathBench(b *testing.B) {
	base := b.TempDir()
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp")}); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkSavePathEditSeparate(b *testing.B) {
	text := savePathBenchConfig()
	for b.Loop() {
		box, _ := EditYAMLForIOS(text, `["mode"]`, "set", `"global"`)
		var answer yamlEditAnswer
		_ = json.Unmarshal([]byte(box.Value), &answer)
		_, _ = YamlToJSON(answer.Text)
		_ = ValidateConfigShape(answer.Text)
	}
}

func BenchmarkSavePathEditCombined(b *testing.B) {
	text := savePathBenchConfig()
	for b.Loop() {
		_, _ = EditYAMLForIOSWithOptions(text, `["mode"]`, "set", `"global"`, `{"document":true,"validateShape":true}`)
	}
}

func BenchmarkSavePathFinalizeSeparate(b *testing.B) {
	setupSavePathBench(b)
	text := savePathBenchConfig()
	for b.Loop() {
		finalized, _ := FinalizeForIOS(text, "")
		_, _ = PlanResourcesForProfile(finalized.Value, RuntimeProfileIOSPacketTunnel)
		_, _ = PlatformConfigIntentJSON(finalized.Value)
		_ = GeodataModeEnabled(finalized.Value)
		_, _ = YamlToJSON(finalized.Value)
	}
}

func BenchmarkSavePathFinalizeCombined(b *testing.B) {
	setupSavePathBench(b)
	text := savePathBenchConfig()
	options := `{"targetProfile":"iosPacketTunnel","plan":true,"intent":true,"geodataMode":true,"topLevelKeys":["allow-lan","mixed-port","port","socks-port"]}`
	for b.Loop() {
		_, _ = FinalizeForIOSWithOptions(text, "", options)
	}
}
