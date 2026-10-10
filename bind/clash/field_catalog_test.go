package clash

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/metacubex/ssh"
)

func fieldCatalog(t *testing.T) []syntaxField {
	t.Helper()
	return mustCatalog(t, "").Fields
}

func TestFieldCatalogTypesAreTheParsersCases(t *testing.T) {
	for _, c := range []struct {
		file, function string
		names          []string
		skip           map[string]bool
	}{
		{"adapter/parser.go", "ParseProxy(", tableNames(fieldProxyTypes()), nil},
		{"listener/parse.go", "ParseListener(", tableNames(fieldListenerTypes()), nil},
		{"adapter/outboundgroup/parser.go", "ParseProxyGroup(", tableNames(fieldGroupTypes()), map[string]bool{"relay": true}},
	} {
		var want []string
		for _, name := range quotedCases(t, upstreamSource(t, c.file), c.function) {
			if !c.skip[name] {
				want = append(want, name)
			}
		}
		got := append([]string(nil), c.names...)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s drifted:\n got  %v\n want %v", c.file, got, want)
		}
	}
}

func tableNames(table []fieldTypeEntry) []string {
	names := make([]string, 0, len(table))
	for _, entry := range table {
		names = append(names, entry.Name)
	}
	return names
}

func TestFieldCatalogShape(t *testing.T) {
	fields := fieldCatalog(t)
	seen := map[string]bool{}
	kinds := map[string]bool{"select": true, "multiSelect": true, "toggle": true, "number": true, "reference": true,
		"text": true, "textList": true, "suggest": true, "object": true, "map": true, "objectList": true}
	for _, field := range fields {
		if seen[field.Path] {
			t.Errorf("%s twice", field.Path)
		}
		seen[field.Path] = true
		if !kinds[field.Kind] {
			t.Errorf("%s: kind %q", field.Path, field.Kind)
		}
		if len(field.Values) > 0 && field.Kind != "select" && field.Kind != "multiSelect" && field.Kind != "suggest" && field.Kind != "textList" {
			t.Errorf("%s: values on a %s", field.Path, field.Kind)
		}
		if (field.Kind == "select" || field.Kind == "multiSelect" || field.Kind == "suggest") && len(field.Values) == 0 {
			t.Errorf("%s: %s without values", field.Path, field.Kind)
		}
		if field.Kind == "reference" && len(field.Refers) == 0 {
			t.Errorf("%s: reference without refers", field.Path)
		}
		if field.Kind == "map" && (field.Key == nil || field.Value == nil) {
			t.Errorf("%s: map without key/value", field.Path)
		}
	}
	for _, annotation := range fieldAnnotations() {
		matched := false
		for _, field := range fields {
			if annotation.matches(field.Path) || (field.Kind == "map" && annotation.Pattern == field.Path+".*") {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("annotation %q matches no key", annotation.Pattern)
		}
	}
}

func TestFieldCatalogReadsValueSetsOffTheCore(t *testing.T) {
	for _, field := range fieldCatalog(t) {
		if field.Path == "tun.stack" {
			for _, want := range []string{"gvisor", "system", "mixed", "mips"} {
				found := false
				for _, value := range field.Values {
					found = found || value == want
				}
				if !found {
					t.Errorf("tun.stack lacks %s: %v", want, field.Values)
				}
			}
			return
		}
	}
	t.Fatal("no tun.stack")
}

func TestFieldCatalogConcurrentCalls(t *testing.T) {
	var wait sync.WaitGroup
	lengths := make([]int, 8)
	for i := range lengths {
		wait.Add(1)
		go func() {
			defer wait.Done()
			box, err := SyntaxCatalogForIOS("")
			if err == nil {
				lengths[i] = len(box.Value)
			}
		}()
	}
	wait.Wait()
	for i, length := range lengths {
		if length == 0 || length != lengths[0] {
			t.Fatalf("call %d: %d bytes, call 0: %d", i, length, lengths[0])
		}
	}
}

func TestFieldCatalogJoinedChoicesAreSplitAsUpstreamSplitsThem(t *testing.T) {
	joined := 0
	for _, field := range fieldList() {
		if field.Kind != "multiSelect" || field.ReflectedKind != "text" {
			if field.Separator != "" {
				t.Errorf("%s: a separator on a %s from a %s", field.Path, field.Kind, field.ReflectedKind)
			}
			continue
		}
		joined++
		if field.Separator == "" {
			t.Errorf("%s: a multiSelect the core reads as one string has no separator", field.Path)
		}
	}
	if joined < 5 {
		t.Fatalf("only %d joined multiSelects: the group and provider exclude-type are gone", joined)
	}
	for file, split := range map[string]string{
		"adapter/outboundgroup/groupbase.go": `strings.Split(opt.ExcludeType, "|")`,
		"adapter/provider/provider.go":       `strings.Split(excludeType, "|")`,
	} {
		if !strings.Contains(upstreamSource(t, file), split) {
			t.Errorf("%s no longer splits with %s", file, split)
		}
	}
	setupConfigPipelineTest(t)
	text := "proxies:\n  - {name: a, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n" +
		"proxy-groups:\n  - name: G\n    type: select\n    proxies: [a]\n    exclude-type: Direct\nrules:\n  - MATCH,G\n"
	var group syntaxField
	for _, field := range fieldList() {
		if field.Path == "proxy-groups[select].exclude-type" {
			group = field
		}
	}
	value, _ := json.Marshal(strings.Join([]string{"Shadowsocks", "Vmess"}, group.Separator))
	edited := runYAMLEdit(t, text, `["proxy-groups",0,"exclude-type"]`, "set", string(value))
	if !edited.OK {
		t.Fatalf("%+v", edited)
	}
	box, err := CompileCheckForIOS(edited.Text, "")
	if err != nil || !strings.Contains(box.Value, `"ok":true`) {
		t.Fatalf("joined choices do not compile: %v %v\n%s", box, err, edited.Text)
	}
}

func TestFieldAnnotationBooleansAreTrueOrFalse(t *testing.T) {
	for i, line := range strings.Split(fieldAnnotationTableText(), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		columns := strings.Split(line, "\t")
		for _, c := range []int{4, 12, 13} {
			if c < len(columns) && columns[c] != "" && columns[c] != "true" && columns[c] != "false" {
				t.Errorf("row %d (%s) column %d: %q", i, columns[0], c, columns[c])
			}
		}
	}
	for _, field := range fieldList() {
		if strings.HasSuffix(field.Path, ".alpn") && strings.HasPrefix(field.Path, "proxies[hysteria2]") && !field.Ordered {
			t.Errorf("%s: an ALPN list is ordered", field.Path)
		}
	}
}

func TestFieldCatalogTypesAreSelectsAndSSHHostKeysAreComplete(t *testing.T) {
	for _, field := range fieldList() {
		if strings.Count(field.Path, ".") == 1 && strings.HasSuffix(field.Path, "].type") && field.Kind != "select" {
			t.Errorf("%s: %s", field.Path, field.Kind)
		}
		if field.Path == "proxy-groups[select].type" && strings.Join(field.Values, ",") != "select,url-test,fallback,load-balance" {
			t.Errorf("%s: %v", field.Path, field.Values)
		}
		if field.Path == "proxies[ssh].host-key-algorithms" {
			have := map[string]bool{}
			for _, value := range field.Values {
				have[value] = true
			}
			for _, algorithm := range append(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys...) {
				if !have[algorithm] {
					t.Errorf("host-key-algorithms lacks %s", algorithm)
				}
			}
			if !field.Ordered {
				t.Error("host-key-algorithms is ordered: the first match wins")
			}
		}
	}
}
