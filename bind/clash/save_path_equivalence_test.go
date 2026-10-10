package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata/router"
	C "github.com/ProjectClash/Clash/constant"
	"go.yaml.in/yaml/v3"
)

func sortedNames(corpus map[string]string) []string {
	names := make([]string, 0, len(corpus))
	for name := range corpus {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func alphabetised(t *testing.T, text string) (string, bool) {
	t.Helper()
	var value map[string]any
	if yaml.Unmarshal([]byte(text), &value) != nil || value == nil {
		return "", false
	}
	out, err := yaml.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(out), true
}

func sameAnswer(t *testing.T, what string, got *StringBox, gotErr error, want *StringBox, wantErr error) bool {
	t.Helper()
	if errorText(gotErr) != errorText(wantErr) {
		t.Errorf("%s: error %q, reference %q", what, errorText(gotErr), errorText(wantErr))
		return false
	}
	if gotErr != nil {
		return true
	}
	if got.Value != want.Value {
		t.Errorf("%s: answer differs from the reference (%d bytes against %d)\n got %.300s\nwant %.300s", what, len(got.Value), len(want.Value), got.Value, want.Value)
		return false
	}
	return true
}

const equivalenceFinalizeOptions = `{"targetProfile":"iosPacketTunnel","plan":true,"intent":true,"geodataMode":true,"topLevelKeys":["allow-lan","mixed-port","port","socks-port","dns"]}`

func withOrderReference(t *testing.T, options, reference string) string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(options), &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["orderReference"] = reference
	out, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

var equivalenceOverrides = []string{
	"",
	`{"patch":{"dns":{"enable":true,"nameserver-policy":{"+.google.com":"8.8.8.8","+.com":"223.5.5.5"}}}}`,
	`{"patch":{"mode":"global","log-level":"debug"},"appendRules":["DOMAIN,override.example.invalid,DIRECT"]}`,
	`{"appendRules":["DOMAIN-SUFFIX,first.example.invalid,DIRECT","MATCH,DIRECT"],"prependRules":true}`,
	`{"patch":{"proxy-groups":[{"name":"🚀 Override","type":"select","proxies":["DIRECT"]}]}}`,
	`{"patch":`,
}

var jsonTreesThatDoNotReadBack = map[string]string{
	"tab-led block":            `{"mode":"rule","rules":["MATCH,DIRECT"],"x-note":"\tone\ntwo"}`,
	"merge key over a scalar":  `{"mode":"rule","rules":["MATCH,DIRECT"],"m":{"<<":1}}`,
	"merge key over a mapping": `{"<<":{"mode":"global"},"mode":"rule","rules":["MATCH,DIRECT"]}`,
	"BOM-led astral name":      `{"proxies":[{"name":"\ufeff\ud83d\ude00 HK","type":"ss","server":"192.0.2.1","port":1,"cipher":"aes-128-gcm","password":"x"}],"proxy-groups":[{"name":"G","type":"select","proxies":["\ufeff\ud83d\ude00 HK"]}],"rules":["MATCH,G"]}`,
	"separators":               `{"a":"x\u2028y","b":"\u0085","c":"\r","d":"a\ufeffb"}`,
}

func assertJSONToYAMLAsTwoCalls(t *testing.T, name, documentJSON, options string) {
	t.Helper()
	box, err := JsonToYAMLWithOptions(documentJSON, options)
	text, textErr := JSONToYaml(documentJSON)
	if errorText(err) != errorText(textErr) {
		t.Errorf("%s: error %q, JSONToYaml %q", name, errorText(err), errorText(textErr))
		return
	}
	if err != nil {
		return
	}
	var answer map[string]json.RawMessage
	decodeAnswer(t, box, nil, &answer)
	var gotText string
	_ = json.Unmarshal(answer["text"], &gotText)
	if gotText != text.Value {
		t.Errorf("%s: text differs from JSONToYaml", name)
		return
	}
	delete(answer, "text")
	gotRest, _ := json.Marshal(answer)
	want, _ := YamlToJSONWithOptions(text.Value, options)
	var wantAnswer map[string]json.RawMessage
	decodeAnswer(t, want, nil, &wantAnswer)
	wantRest, _ := json.Marshal(wantAnswer)
	if !bytes.Equal(gotRest, wantRest) {
		t.Errorf("%s: %s, YamlToJSONWithOptions %s", name, gotRest, wantRest)
	}
}

func textOf(t *testing.T, handle *DocumentHandle) string {
	t.Helper()
	box, err := handle.Text()
	if err != nil {
		t.Fatal(err)
	}
	return box.Value
}

func assertHandleAnswersAsText(t *testing.T, what string, handle *DocumentHandle, original string) {
	t.Helper()
	text := textOf(t, handle)
	for _, options := range []string{`{}`, `{"validateShape":true}`} {
		got, gotErr := handle.Document(options)
		want, wantErr := YamlToJSONWithOptions(text, options)
		sameAnswer(t, what+" document "+options, got, gotErr, want, wantErr)
	}
	got, gotErr := handle.Plan("iosPacketTunnel")
	want, wantErr := PlanResourcesForProfile(text, "iosPacketTunnel")
	sameAnswer(t, what+" plan", got, gotErr, want, wantErr)
	got, gotErr = handle.FinalizeWithOptions("", equivalenceFinalizeOptions)
	want, wantErr = legacyFinalizeForIOSWithOptions(text, "", withOrderReference(t, equivalenceFinalizeOptions, original))
	sameAnswer(t, what+" finalize", got, gotErr, want, wantErr)
	got, gotErr = handle.FinalizeWithOptions("", withOrderReference(t, equivalenceFinalizeOptions, text))
	want, wantErr = legacyFinalizeForIOSWithOptions(text, "", withOrderReference(t, equivalenceFinalizeOptions, text))
	sameAnswer(t, what+" finalize (own reference)", got, gotErr, want, wantErr)
}

func TestADocumentHandleNamesTheTextsLinesInAnError(t *testing.T) {
	setupConfigPipelineTest(t)
	handle, err := OpenDocumentForIOS("mode: rule\nrules:\n  - MATCH,DIRECT\n")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	documentJSON := `{"mode":"rule","dns":{"enable":true},"port":"nope","rules":["MATCH,DIRECT"]}`
	fallbacks := finalizedTreeFallbacks.Load()
	got, gotErr := handle.SetDocumentJSON(documentJSON, `{"validateShape":true}`)
	want, wantErr := JsonToYAMLWithOptions(documentJSON, `{"validateShape":true}`)
	sameAnswer(t, "set document", got, gotErr, want, wantErr)
	if !strings.Contains(got.Value, "line ") {
		t.Errorf("the shape error names no line: %s", got.Value)
	}
	assertHandleAnswersAsText(t, "bad shape", handle, "mode: rule\nrules:\n  - MATCH,DIRECT\n")
	if finalizedTreeFallbacks.Load() == fallbacks {
		t.Error("no answer was read again from the text")
	}
}

func TestADocumentHandleOpensOnlyOneConfiguration(t *testing.T) {
	for name, text := range map[string]string{
		"age":              "age-encryption.org/v1\n-> X25519 abc\n",
		"two documents":    "mode: rule\n---\nmode: global\n",
		"a list":           "- a\n- b\n",
		"a scalar":         "rule\n",
		"empty":            "",
		"does not parse":   "mode: [rule\n",
		"comments only":    "# nothing\n",
		"document markers": "---\nmode: rule\n...\n---\nmode: global\n",
	} {
		if handle, err := OpenDocumentForIOS(text); err == nil {
			handle.Close()
			t.Errorf("%s: opened", name)
		}
	}
	for name, text := range map[string]string{
		"crlf":    "mode: rule\r\nrules:\r\n  - MATCH,DIRECT\r\n",
		"marker":  "---\nmode: rule\n",
		"anchors": "base: &b {enable: true}\ndns: *b\n",
	} {
		handle, err := OpenDocumentForIOS(text)
		if err != nil {
			t.Errorf("%s: refused a configuration that reads: %v", name, err)
			continue
		}
		setupConfigPipelineTest(t)
		assertHandleAnswersAsText(t, name, handle, text)
		got, gotErr := handle.Edit(`["mode"]`, "set", `"global"`)
		want, wantErr := EditYAMLForIOS(text, `["mode"]`, "set", `"global"`)
		sameAnswer(t, name+" edit", got, gotErr, want, wantErr)
		handle.Close()
	}
}

func TestADocumentHandleRefusesWithoutChanging(t *testing.T) {
	const text = "mode: rule\nrules:\n  - MATCH,DIRECT\n"
	handle, err := OpenDocumentForIOS(text)
	if err != nil {
		t.Fatal(err)
	}
	if box, err := handle.Edit(`["no","such"]`, "set", `1`); err != nil || !strings.Contains(box.Value, `"ok":false`) {
		t.Errorf("refused edit answered %v %v", box, err)
	}
	if _, err := handle.SetDocumentJSON(`[1]`, `{}`); err == nil {
		t.Error("a list was set as the document")
	}
	if _, err := handle.MergeOverride(`{"patch":`); err == nil {
		t.Error("an override that is not JSON was merged")
	}
	if textOf(t, handle) != text {
		t.Error("a refused call changed the text")
	}
	handle.Close()
	handle.Close()
	if _, err := handle.Text(); err == nil {
		t.Error("a closed handle answered")
	}
	if _, err := handle.FinalizeWithOptions("", `{}`); err == nil {
		t.Error("a closed handle finalized")
	}
}

func TestADocumentHandleSerializesItsCalls(t *testing.T) {
	setupConfigPipelineTest(t)
	handle, err := OpenDocumentForIOS("mode: rule\nlog-level: info\nrules:\n  - MATCH,DIRECT\n")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				switch (worker + i) % 5 {
				case 0:
					_, _ = handle.Edit(`["log-level"]`, "set", fmt.Sprintf(`"level-%d"`, i))
				case 1:
					_, _ = handle.Document(`{"validateShape":true}`)
				case 2:
					_, _ = handle.Plan("iosPacketTunnel")
				case 3:
					_, _ = handle.FinalizeWithOptions("", `{"plan":true,"targetProfile":"iosPacketTunnel"}`)
				case 4:
					_, _ = handle.SetDocumentJSON(fmt.Sprintf(`{"mode":"rule","log-level":"set-%d","rules":["MATCH,DIRECT"]}`, i), `{}`)
				}
			}
		}(worker)
	}
	wg.Wait()
	text := textOf(t, handle)
	got, _ := handle.Document(`{}`)
	want, _ := YamlToJSONWithOptions(text, `{}`)
	if got.Value != want.Value {
		t.Error("after concurrent calls the handle's document is not its text's")
	}
}

func TestTheGeoCachesPrepareForAListAsForItsText(t *testing.T) {
	home := setupConfigPipelineTest(t)
	C.SetHomeDir(home)
	resetGeodataFlagsForYardstick(t)
	writeGeodataAtomically(t, filepath.Join(home, "GeoSite.dat"), &router.GeoSiteList{Entry: []*router.GeoSite{
		{CountryCode: "AUDIT", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "audit.example.com"}}},
	}})
	writeGeodataAtomically(t, filepath.Join(home, "GeoIP.dat"), &router.GeoIPList{Entry: []*router.GeoIP{
		{CountryCode: "AUDIT", Cidr: []*router.CIDR{{Ip: []byte{203, 0, 113, 0}, Prefix: 24}}},
	}})
	document := "geodata-mode: true\nrules:\n - GEOSITE,Audit,DIRECT\n - GEOIP,audit,DIRECT\n - MATCH,REJECT\n"
	if _, err := PrepareGeoSiteCache(document); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareGeoIPCache(document, true); err != nil {
		t.Fatal(err)
	}
	site, _ := json.Marshal(GeoSiteCategoriesIn(document))
	ip, _ := json.Marshal(GeoIPCountriesIn(document))
	wantSite, _ := PrepareGeoSiteCache(document)
	gotSite, err := PrepareGeoSiteCacheForCategories(string(site))
	if err != nil || gotSite != wantSite {
		t.Errorf("geosite: %q (%v), the text %q", gotSite, err, wantSite)
	}
	wantIP, _ := PrepareGeoIPCache(document, true)
	gotIP, err := PrepareGeoIPCacheForCountries(string(ip), true)
	if err != nil || gotIP != wantIP {
		t.Errorf("geoip: %q (%v), the text %q", gotIP, err, wantIP)
	}
	if got, _ := PrepareGeoIPCacheForCountries(string(ip), false); got != "geoip: skipped, tunnel reads geoip.metadb" {
		t.Errorf("geodata mode off: %q", got)
	}
	if got, _ := PrepareGeoSiteCacheForCategories(`[" AUDIT ","audit","bad name","",":"]`); got != wantSite {
		t.Errorf("an unnormalised list: %q, want %q", got, wantSite)
	}
	if got, _ := PrepareGeoIPCacheForCountries(`["!AUDIT","lan","audit"]`, true); got != wantIP {
		t.Errorf("an unnormalised country list: %q, want %q", got, wantIP)
	}
	if got, _ := PrepareGeoSiteCacheForCategories(`[]`); got != "geosite: no categories named" {
		t.Errorf("an empty list: %q", got)
	}
	if _, err := PrepareGeoSiteCacheForCategories(`{"not":"a list"}`); err == nil {
		t.Error("a list that is not one was accepted")
	}
}

var walkAdversaries = []string{
	"a: 1\na: 2\n",
	"1: a\n\"1\": b\n",
	"1: a\n0x1: b\n",
	"? [a, b]\n: c\n",
	"? {a: 1}\n: c\n",
	"~: 1\nnull: 2\n",
	"!!int abc: 1\n",
	"!!binary '***': 1\n",
	"!!binary aGVsbG8=: 1\n",
	"!!str 123: 1\n",
	"!!float 1: x\n",
	"'<<': 1\n",
	"\"<<\": {a: 1}\n",
	"a: !!int abc\n",
	"a: !!binary aGVsbG8=\n",
	"a: !!binary '***'\n",
	"a: !!float 1\n",
	"a: !!str 123\n",
	"a: !custom value\n",
	"a: !!merge x\n",
	"a: .nan\n",
	"a: [.inf, -.inf, 1_000, 0x1F, 0o17, 18446744073709551615, 1e400, 2001-12-14, '2001-12-14', ~, null, true, 'true', '']\n",
	"a: '<tag>&amp;'\nb: \"\\U0001F600 \\u2028\"\n",
	"a: |\n  literal\n  text\nb: >\n  folded\n  text\n",
	"a: {b: 1, b: 2}\n",
	"a: [{b: 1}, {b: 1, b: 2}]\n",
	"a: &x 1\nb: *x\n",
	"a: &x {b: 1}\n*x : 2\n",
	"a: &x b\n*x : 2\nb: 3\n",
	"base: &b {x: 1}\nother: {<<: *b, y: 2}\n",
	"base: &b {x: 1}\nother: {<<: *b, x: 2, x: 3}\n",
	"a: {<<: {x: 1}, y: 2}\n",
	"a: {<<: [{x: 1}, {x: 2, z: 3}], y: 2}\n",
	"a: {<<: 1}\n",
	"a: &a [x, x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\ne: [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]\n",
}

func walkAdversaryTrees() map[string]*yaml.Node {
	scalar := func(tag, value string) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	}
	mapping := func(content ...*yaml.Node) *yaml.Node {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: content}
	}
	return map[string]*yaml.Node{
		"untagged merge key":      mapping(scalar("", "<<"), scalar("!!int", "1")),
		"untagged merge mapping":  mapping(scalar("", "<<"), mapping(scalar("!!str", "x"), scalar("!!int", "1")), scalar("!!str", "y"), scalar("!!int", "2")),
		"untagged key":            mapping(scalar("", "a"), scalar("!!int", "1")),
		"str-tagged merge key":    mapping(scalar("!!str", "<<"), scalar("!!int", "1")),
		"long str tag":            mapping(scalar("!!str", "a"), scalar("tag:yaml.org,2002:str", "123")),
		"plain str 123":           mapping(scalar("!!str", "a"), scalar("!!str", "123")),
		"zero node":               mapping(scalar("!!str", "a"), &yaml.Node{}),
		"document inside":         mapping(scalar("!!str", "a"), &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{scalar("!!int", "1")}}),
		"anchored key":            mapping(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "a", Anchor: "k"}, scalar("!!int", "1")),
		"duplicate built keys":    mapping(scalar("!!str", "a"), scalar("!!int", "1"), scalar("!!str", "a"), scalar("!!int", "2")),
		"int-tagged value string": mapping(scalar("!!str", "a"), scalar("!!int", "x")),
	}
}

func jsonTextAdversaries() []string {
	texts := []string{
		`{}`, `[]`, `{"a":1}`, " \t\r\n{ \"a\" : [ 1 , 2 ] , \"b\" : { } }\n", `{"a":1,"a":2}`, `{"a":1,"\u0061":2}`,
		`{"a":"\u00e9\ud83d\ude00\ud800x\udc00"}`, `{"a":"é😀"}`, "{\"a\":\"\xff\"}", "{\"a\":\"\xed\xa0\x80\"}", "{\"a\":\"\xc3\"}",
		"{\"a\":\"tab\there\"}", `{"a":"\/\b\f\n\r\t\\\""}`, `{"a":"\u0000"}`, `{"a":"\u12"}`, `{"a":"\x"}`,
		`{"a":-0,"b":0.5e+10,"c":1E5,"d":-1.25e-3,"e":123456789012345678901234567890,"f":0}`,
		`{"a":01}`, `{"a":1.}`, `{"a":.5}`, `{"a":+1}`, `{"a":1e}`, `{"a":-}`,
		`{"a":true,"b":false,"c":null}`, `{"a":tru}`, `{"a":nul}`, `{"a":1,}`, `[1,]`, `{"a":1}{"b":2}`, `{"a":1} x`, `{"a":1}  `,
		"\ufeff{}", ``, ` `, `1`, `"x"`, `[1]`, `null`, `{"a"}`, `{"a":}`, `{:1}`, `{"a" 1}`, `{"a":[1 2]}`, `{"a":"x`,
		`{"a":{"b":{"c":[{"d":1,"d":2}]}}}`, `{"a":[{"b":1},{"b":1}]}`, `{"<<":{"x":1},"~":null,"":""}`,
	}
	deep := func(levels int) string {
		return `{"a":` + strings.Repeat("[", levels) + "1" + strings.Repeat("]", levels) + "}"
	}
	return append(texts, deep(9998), deep(9999), deep(10000))
}

func textOf2(box *StringBox) string {
	if box == nil {
		return ""
	}
	return box.Value
}

func TestADocumentHandleEditsWithoutReadingItsTextAgain(t *testing.T) {
	original := "mixed-port: 7890\nproxies:\n  - {name: a, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,DIRECT\n"
	handle, err := OpenDocumentForIOS(original)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	text := original
	edits := [][3]string{
		{`["rules",0]`, "set", `"DOMAIN-SUFFIX,example.invalid,DIRECT"`},
		{`["rules",1]`, "insert", `"MATCH,DIRECT"`},
		{`["mixed-port"]`, "set", `7891`},
	}
	for _, edit := range edits {
		rememberParsedYAML(nil)
		reads := editTextReads.Load()
		got, gotErr := handle.Edit(edit[0], edit[1], edit[2])
		if editTextReads.Load() != reads {
			t.Fatalf("%v: the handle's Edit read its text again", edit)
		}
		parsedYAMLCacheMu.Lock()
		cached := parsedYAMLCache
		parsedYAMLCacheMu.Unlock()
		if cached != nil {
			t.Fatalf("%v: the handle's Edit put its read in the edit cache, which outlives Close", edit)
		}
		rememberParsedYAML(nil)
		want, wantErr := EditYAMLForIOS(text, edit[0], edit[1], edit[2])
		if editTextReads.Load() != reads+1 {
			t.Fatalf("%v: EditYAMLForIOS did not read the text", edit)
		}
		if !sameAnswer(t, fmt.Sprint(edit), got, gotErr, want, wantErr) {
			return
		}
		var answer struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal([]byte(want.Value), &answer); err != nil || answer.Text == "" {
			t.Fatalf("%v: %s", edit, want.Value)
		}
		text = answer.Text
	}
	box, err := handle.Document(`{}`)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal([]byte(box.Value), &document); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.SetDocumentJSON(string(document.Document), `{}`); err != nil {
		t.Fatal(err)
	}
	rememberParsedYAML(nil)
	reads := editTextReads.Load()
	if _, err := handle.Edit(`["mixed-port"]`, "set", `7892`); err != nil {
		t.Fatal(err)
	}
	if editTextReads.Load() != reads+1 {
		t.Errorf("an Edit after SetDocumentJSON read %d texts, not 1", editTextReads.Load()-reads)
	}
	duplicated := "a: 1\na: 2\n"
	refusing, err := OpenDocumentForIOS(duplicated)
	if err != nil {
		t.Fatal(err)
	}
	defer refusing.Close()
	rememberParsedYAML(nil)
	got, gotErr := refusing.Edit(`["b"]`, "set", `1`)
	rememberParsedYAML(nil)
	want, wantErr := EditYAMLForIOS(duplicated, `["b"]`, "set", `1`)
	sameAnswer(t, "duplicate keys", got, gotErr, want, wantErr)
	if !strings.Contains(want.Value, "does not parse") {
		t.Errorf("EditYAMLForIOS accepted a text that does not decode: %s", want.Value)
	}
}

func TestADocumentHandleReadsItsTextWhenItsJSONTreeWouldNot(t *testing.T) {
	setupConfigPipelineTest(t)
	original := "mode: rule\nrules:\n  - MATCH,DIRECT\n"
	for _, name := range sortedNames(jsonTreesThatDoNotReadBack) {
		documentJSON := jsonTreesThatDoNotReadBack[name]
		handle, err := OpenDocumentForIOS(original)
		if err != nil {
			t.Fatal(err)
		}
		got, gotErr := handle.SetDocumentJSON(documentJSON, `{"validateShape":true}`)
		want, wantErr := JsonToYAMLWithOptions(documentJSON, `{"validateShape":true}`)
		sameAnswer(t, name+" set document", got, gotErr, want, wantErr)
		assertHandleAnswersAsText(t, name, handle, original)
		text := textOf(t, handle)
		for i, override := range equivalenceOverrides[:3] {
			got, gotErr := handle.MergeOverride(override)
			want, wantErr := MergeOverrideForIOS(text, override)
			sameAnswer(t, fmt.Sprintf("%s merge %d", name, i), got, gotErr, want, wantErr)
			if gotErr == nil {
				_, _ = handle.SetDocumentJSON(documentJSON, `{}`)
			}
		}
		got, gotErr = handle.Edit(`["mode"]`, "set", `"global"`)
		want, wantErr = EditYAMLForIOS(text, `["mode"]`, "set", `"global"`)
		sameAnswer(t, name+" edit", got, gotErr, want, wantErr)
		handle.Close()
	}
}

func TestJSONTreesAnswerAsTheirTexts(t *testing.T) {
	setupConfigPipelineTest(t)
	pieces := []string{"a", "HK", " ", "\\t", "\\n", "\\r", "#", ": ", "- ", "'", "\\\"", "\\\\", "<<", "~", "null", "true", "1", "0x1F", "1e3", ".inf", "\\u00e9", "\\ud83d\\ude00", "\\ufeff", "\\u2028", "\\u0085", "\\u0000", "%", "@", "`", "|", ">"}
	random := rand.New(rand.NewSource(3801))
	var trustedPieces []string
	for _, piece := range pieces {
		if !strings.Contains(piece, `\`) && piece != "<<" {
			trustedPieces = append(trustedPieces, piece)
		}
	}
	from := pieces
	word := func() string {
		var b strings.Builder
		for n := random.Intn(4); n >= 0; n-- {
			b.WriteString(from[random.Intn(len(from))])
		}
		return b.String()
	}
	original := "mode: rule\nrules:\n  - MATCH,DIRECT\n"
	handle, err := OpenDocumentForIOS(original)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	trusted := 0
	for round := 0; round < 400; round++ {
		from = pieces
		if round%2 == 0 {
			from = trustedPieces
		}
		var b strings.Builder
		b.WriteString(`{"mode":"rule","rules":["MATCH,DIRECT"]`)
		for n := random.Intn(4); n >= 0; n-- {
			fmt.Fprintf(&b, `,"%s":{"%s":"%s","list":["%s","%s"]}`, word(), word(), word(), word(), word())
		}
		b.WriteString("}")
		documentJSON := b.String()
		if _, document, err := jsonDocumentAsYAML(documentJSON); err == nil && document != nil {
			trusted++
		}
		assertJSONToYAMLAsTwoCalls(t, documentJSON, documentJSON, `{"validateShape":true}`)
		got, gotErr := handle.SetDocumentJSON(documentJSON, `{"validateShape":true}`)
		want, wantErr := JsonToYAMLWithOptions(documentJSON, `{"validateShape":true}`)
		if !sameAnswer(t, documentJSON, got, gotErr, want, wantErr) || gotErr != nil {
			continue
		}
		text := textOf(t, handle)
		got, gotErr = handle.Plan("iosPacketTunnel")
		want, wantErr = PlanResourcesForProfile(text, "iosPacketTunnel")
		sameAnswer(t, documentJSON+" plan", got, gotErr, want, wantErr)
		got, gotErr = handle.FinalizeWithOptions("", equivalenceFinalizeOptions)
		want, wantErr = legacyFinalizeForIOSWithOptions(text, "", withOrderReference(t, equivalenceFinalizeOptions, original))
		sameAnswer(t, documentJSON+" finalize", got, gotErr, want, wantErr)
	}
	if trusted < 150 {
		t.Errorf("only %d of 400 trees were trusted: the test no longer tests the tree", trusted)
	}
}

func TestAFinalizedTreeHoldsWhatItsTextHolds(t *testing.T) {
	setupConfigPipelineTest(t)
	name := "\ufeff\U0001F600 HK"
	config := fmt.Sprintf("mode: rule\nproxies:\n  - {name: %q, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: x}\nproxy-groups:\n  - {name: G, type: select, proxies: [%q]}\nrules:\n  - MATCH,G\n", name, name)
	options := `{"targetProfile":"iosPacketTunnel","plan":true,"intent":true,"geodataMode":true,"topLevelKeys":["proxies","proxy-groups"]}`
	got, gotErr := FinalizeForIOSWithOptions(config, "", options)
	want, wantErr := legacyFinalizeForIOSWithOptions(config, "", options)
	sameAnswer(t, "BOM-led name", got, gotErr, want, wantErr)
	if gotErr == nil && !strings.Contains(got.Value, "\\U0001F600") && !strings.Contains(got.Value, "\U0001F600") {
		t.Errorf("the finalized configuration lost the emoji: %s", got.Value)
	}
	var answer struct {
		Text string `json:"text"`
	}
	if gotErr == nil {
		_ = json.Unmarshal([]byte(got.Value), &answer)
		document, err := YamlToJSON(answer.Text)
		if err != nil || !strings.Contains(document.Value, "\U0001F600 HK") {
			t.Errorf("the finalized text reads back without the name: %v", err)
		}
	}
}

func TestAWrittenTreeThatDoesNotReadBackAnswersAsItsText(t *testing.T) {
	setupConfigPipelineTest(t)
	config := "mode: rule\nproxies:\n  - {name: \"\\n  x\", type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,DIRECT\n"
	got, gotErr := FinalizeForIOSWithOptions(config, "", equivalenceFinalizeOptions)
	want, wantErr := legacyFinalizeForIOSWithOptions(config, "", equivalenceFinalizeOptions)
	sameAnswer(t, "finalize", got, gotErr, want, wantErr)
	for i, override := range equivalenceOverrides {
		got, gotErr := MergeOverrideForIOS(config, override)
		want, wantErr := legacyMergeOverride(config, override)
		sameAnswer(t, fmt.Sprintf("override %d", i), got, gotErr, want, wantErr)
	}
	handle, err := OpenDocumentForIOS(config)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	merged, err := handle.MergeOverride(equivalenceOverrides[2])
	if err != nil {
		t.Fatal(err)
	}
	gotPlan, gotPlanErr := handle.Plan(RuntimeProfileIOSPacketTunnel)
	wantPlan, wantPlanErr := PlanResourcesForProfile(merged.Value, RuntimeProfileIOSPacketTunnel)
	sameAnswer(t, "the handle's plan after a merge", gotPlan, gotPlanErr, wantPlan, wantPlanErr)
}
