package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/clashindex"
	RC "github.com/ProjectClash/Clash/rules/common"
	"github.com/ProjectClash/Clash/tunnel"
	"go.yaml.in/yaml/v3"
)

func TestABlockScalarRuleRoutesTheSamePublishedInPlace(t *testing.T) {
	setupForMatch(t)
	source := "rules:\n  - >2-\n    DOMAIN-SUFFIX,\n    example.com,REJECT\n  - MATCH,DIRECT\n"
	publish := func(inPlace bool) string {
		finalizeReadsRulesInPlace = inPlace
		defer func() { finalizeReadsRulesInPlace = true }()
		published, _ := finalizeWithRuleIndex(t, source, t.TempDir())
		return published
	}
	for _, inPlace := range []bool{false, true} {
		if got := runMatch(t, publish(inPlace), "", `{"host":"www.example.com"}`); got.Policy != "REJECT" {
			t.Errorf("in place %v: %+v", inPlace, got)
		}
	}
}

func TestAPublishReadingRulesInPlaceTakesWhatTheParseTakes(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n  - {name: P, type: direct}\nrules:\n")
	for i := 0; i < 100000; i++ {
		b.WriteString("  - MATCH,DIRECT\n")
	}
	b.WriteString("sub-rules:\n  base: &r [")
	for i := 0; i < 1000; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "'DOMAIN,d%d.example,DIRECT'", i)
	}
	b.WriteString("]\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "  s%d: *r\n", i)
	}
	document := b.String()
	if err := ValidateConfigShape(document); err != nil {
		t.Fatalf("the shape check: %v", err)
	}
	publish := func(inPlace bool) error {
		finalizeReadsRulesInPlace = inPlace
		defer func() { finalizeReadsRulesInPlace = true }()
		resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": t.TempDir()})
		_, err := FinalizeForIOS(document, string(resources))
		return err
	}
	if held, inPlace := publish(false), publish(true); fmt.Sprint(held) != fmt.Sprint(inPlace) {
		t.Fatalf("held: %v, in place: %v", held, inPlace)
	}
}

func TestARunningSliceIsFilteredByTheTypesItsRulesCouldBeWrittenAs(t *testing.T) {
	previous := tunnel.RuleTable()
	t.Cleanup(func() {
		tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), previous, nil, map[string]P.RuleProvider{})
	})
	for _, line := range []string{
		"IP-CIDR,2001:db8::/32,DIRECT",
		"IP-CIDR6,10.0.0.0/8,DIRECT",
		"IP-CIDR,10.0.0.0/8,DIRECT,src",
		"IP-CIDR6,2001:db8::/32,DIRECT,src",
		"IP-SUFFIX,0.0.0.1/8,DIRECT,src",
		"GEOIP,lan,DIRECT,src",
		"IP-CIDR,::ffff:10.0.0.0/104,DIRECT",
		"DOMAIN,a.example,DIRECT",
	} {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			t.Fatal(err)
		}
		tunnel.UpdateProxiesAndRuleTable(tunnel.Proxies(), tunnel.Providers(), C.RuleList{rule}, nil, map[string]P.RuleProvider{})
		filter, _ := json.Marshal([]string{tp})
		var page rulesPage
		if err := json.Unmarshal([]byte(RulesPageJSON(0, 10, string(filter))), &page); err != nil || len(page.Rules) != 1 {
			t.Errorf("%s by %s: %v %+v", line, tp, err, page)
		}
	}
}

func TestTheCollectorsPercentIsRestoredAfterInterleavedCallers(t *testing.T) {
	previous := debug.SetGCPercent(100)
	defer debug.SetGCPercent(previous)
	source := "rules:\n" + strings.Repeat("  - DOMAIN,a.test,DIRECT\n", 200000)
	for _, catalogFirst := range []bool{true, false} {
		scanning := make(chan struct{})
		done := make(chan struct{})
		if catalogFirst {
			go func() {
				release := enterCompactHeap()
				close(scanning)
				c, _ := openRuleCatalog(source)
				if c != nil {
					c.Close()
				}
				release()
				close(done)
			}()
			<-scanning
			_, _ = withCompactHeap(func() (struct{}, error) { <-done; return struct{}{}, nil })
		} else {
			_, _ = withCompactHeap(func() (struct{}, error) {
				go func() {
					c, _ := openRuleCatalog(source)
					if c != nil {
						c.Close()
					}
					close(done)
				}()
				time.Sleep(20 * time.Millisecond)
				return struct{}{}, nil
			})
			<-done
		}
		if got := debug.SetGCPercent(100); got != 100 {
			t.Fatalf("catalog first %v: the percent is %d after both", catalogFirst, got)
		}
	}
}

func TestTheAtPathCallsRefuseAFIFOAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip(err)
	}
	for name, call := range map[string]func() error{
		"ValidateConfigShapeAtPath": func() error { return ValidateConfigShapeAtPath(path) },
		"PlanResourcesForProfileAtPath": func() error {
			_, err := PlanResourcesForProfileAtPath(path, RuntimeProfileIOSPacketTunnel)
			return err
		},
		"ProviderAgeSecretKeysJSONAtPath": func() error { _, err := ProviderAgeSecretKeysJSONAtPath(path); return err },
		"YamlToJSONOmittingAtPath":        func() error { _, err := YamlToJSONOmittingAtPath(path, `["rules"]`); return err },
		"FinalizeForIOSAtPath":            func() error { _, err := FinalizeForIOSAtPath(path, ""); return err },
		"FinalizeForIOSWithOptionsAtPath": func() error { _, err := FinalizeForIOSWithOptionsAtPath(path, "", ""); return err },
		"OpenRuleCatalogForIOSAtPath":     func() error { _, err := OpenRuleCatalogForIOSAtPath(path); return err },
		"OpenRuleCatalogForPublishedAtPath": func() error {
			_, err := OpenRuleCatalogForPublishedAtPath(path)
			return err
		},
		"clashindex.OpenVerified": func() error { _, err := clashindex.OpenVerified(path, [32]byte{}); return err },
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s took a FIFO", name)
			}
		case <-time.After(3 * time.Second):
			w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if err == nil {
				w.Close()
			}
			<-done
			t.Errorf("%s waited on a FIFO", name)
		}
	}
}

func TestTheOfflineMatchOfAPublishWhoseIndexIsGoneSaysSo(t *testing.T) {
	setupForMatch(t)
	published, root := finalizeWithRuleIndex(t, "rules: ['MATCH,REJECT']\n", t.TempDir())
	if err := os.Remove(root["x-clash-rule-index"].(map[string]any)["path"].(string)); err != nil {
		t.Fatal(err)
	}
	got, err := MatchRuleForIOS(published, "", `{"host":"example.test"}`)
	if err == nil || !strings.Contains(err.Error(), "the rule index is not here") {
		t.Fatalf("%v %v", got, err)
	}
}

func TestADocumentNamingAFIFOIsRefusedAtOnce(t *testing.T) {
	setupForMatch(t)
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	sum := strings.Repeat("ab", 32)
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel, "ruleIndexDirectory": t.TempDir(), "nodeLibraryDirectory": t.TempDir()})
	within := func(name string, call func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				w.Close()
			}
			<-done
			t.Errorf("%s waited on a FIFO", name)
		}
	}
	index := "mode: rule\nproxies:\n  - {name: P, type: direct}\nx-clash-rule-index: {path: " + fifo + ", sha256: \"" + sum + "\"}\n"
	library := "mode: rule\nx-clash-node-library: {path: " + fifo + ", sha256: \"" + sum + "\"}\nrules:\n  - MATCH,DIRECT\n"
	within("FinalizeForIOS naming a FIFO index", func() error { _, err := FinalizeForIOS(index, string(resources)); return err })
	within("FinalizeForIOS naming a FIFO library", func() error { _, err := FinalizeForIOS(library, string(resources)); return err })
	within("MatchRuleForIOS naming a FIFO library", func() error {
		_, err := MatchRuleForIOS(library, "", `{"host":"a.test"}`)
		return err
	})
	within("a publish after them", func() error {
		_, err := FinalizeForIOS("rules:\n  - MATCH,DIRECT\n", string(resources))
		return err
	})
}

func TestTheProjectionAndTheDeviationsOfAPublishWhoseIndexIsGoneSaySo(t *testing.T) {
	setupForMatch(t)
	published, root := finalizeWithRuleIndex(t, "proxies:\n  - {name: P, type: direct}\nrules:\n  - DOMAIN,a.example,P\n  - MATCH,DIRECT\n", t.TempDir())
	if err := os.Remove(root["x-clash-rule-index"].(map[string]any)["path"].(string)); err != nil {
		t.Fatal(err)
	}
	doc, err := NewConfigDocument(published)
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()
	if _, err := doc.ProjectionJSON("merged", `["ruleFacts"]`); err == nil || !strings.Contains(err.Error(), "the rule index is not here") {
		t.Errorf("projection: %v", err)
	}
	if _, err := ConfigDeviationsJSON(published, RuntimeProfileIOSPacketTunnel); err == nil || !strings.Contains(err.Error(), "the rule index is not here") {
		t.Errorf("deviations: %v", err)
	}
}

func TestAnEditOfABlockScalarRuleKeepsWhatFollows(t *testing.T) {
	for _, source := range []string{
		"rules:\n  - >-\n    MATCH,DIRECT\nmixed-port: 7890\n",
		"rules:\n  - |+\n    DOMAIN,a.example,DIRECT\n\n  - MATCH,DIRECT\nmixed-port: 7890\n",
		"rules:\n  - DOMAIN,a.example,DIRECT\n  - >2-\n    MATCH,\n    DIRECT\nmixed-port: 7890\n",
		"rules:\r\n  - >-\r\n    MATCH,DIRECT\r\nmixed-port: 7890\r\n",
	} {
		unchanged, err := EditRulesForIOS(source, `[]`)
		if err != nil || unchanged.Text != source {
			t.Fatalf("%q: an empty edit: %v %q", source, err, unchanged.Text)
		}
		catalog, err := OpenRuleCatalogForIOS(source)
		if err != nil {
			t.Fatal(err)
		}
		last := catalog.Total() - 1
		catalog.Close()
		for _, ops := range []string{
			fmt.Sprintf(`[{"op":"delete","index":%d}]`, last),
			fmt.Sprintf(`[{"op":"replace","index":%d,"rule":"MATCH,REJECT"}]`, last),
			`[{"op":"replace","index":0,"rule":"DOMAIN,b.example,REJECT"}]`,
			`[{"op":"insert","index":0,"rule":"DOMAIN,c.example,REJECT"}]`,
			fmt.Sprintf(`[{"op":"move","index":0,"to":%d}]`, last),
		} {
			edited, err := EditRulesForIOS(source, ops)
			if err != nil {
				t.Fatalf("%q %s: %v", source, ops, err)
			}
			var document struct {
				Rules []string `yaml:"rules"`
				Port  int      `yaml:"mixed-port"`
			}
			if err := yaml.Unmarshal([]byte(edited.Text), &document); err != nil || document.Port != 7890 || len(document.Rules) != int(edited.Total) {
				t.Errorf("%q %s: %v %+v\n%s", source, ops, err, document, edited.Text)
			}
		}
	}
}

func TestThePlanOfAPublishWhoseIndexIsGoneSaysSo(t *testing.T) {
	setupForMatch(t)
	published, root := finalizeWithRuleIndex(t, "rules: ['GEOSITE,cn,REJECT', 'MATCH,DIRECT']\n", t.TempDir())
	if err := os.Remove(root["x-clash-rule-index"].(map[string]any)["path"].(string)); err != nil {
		t.Fatal(err)
	}
	if plan, err := PlanResourcesForProfile(published, RuntimeProfileIOSPacketTunnel); err == nil || !strings.Contains(err.Error(), "the rule index is not here") {
		t.Fatalf("plan: %v %v", plan, err)
	}
}

func TestARunningSliceIsNotFilteredByATypeNoLineWrites(t *testing.T) {
	rule, err := R.ParseRule("DOMAIN-SUFFIX", "example.com", "REJECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tp := range []string{"DOMAINSUFFIX", "DOMAIN", "IP-CIDR"} {
		if writtenRuleTypeIn(C.RuleList{rule}, 0, map[string]bool{tp: true}) {
			t.Errorf("DOMAIN-SUFFIX passed as %s", tp)
		}
	}
	if !writtenRuleTypeIn(C.RuleList{rule}, 0, map[string]bool{"DOMAIN-SUFFIX": true}) {
		t.Error("DOMAIN-SUFFIX did not pass as itself")
	}
}

func TestAConfigurationAtAPathNamingAFIFOIndexIsRefusedAtOnce(t *testing.T) {
	dir := t.TempDir()
	index := filepath.Join(dir, "rules.index")
	if err := syscall.Mkfifo(index, 0o600); err != nil {
		t.Skip(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("x-clash-rule-index: {path: %q, sha256: %q}\n", index, strings.Repeat("0", 64))), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := FinalizeForIOSAtPath(path, ""); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO index published")
		}
	case <-time.After(3 * time.Second):
		if w, err := os.OpenFile(index, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			defer w.Close()
		}
		<-done
		t.Fatal("FinalizeForIOSAtPath waited on a FIFO index")
	}
}

func TestAnEditKeepsTheCommentsAfterABlockScalarRule(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		source := strings.ReplaceAll("rules:\n  - >-\n    DOMAIN,a.example,DIRECT\n  # keep me\n\n  - MATCH,DIRECT\n  # about the last\nmixed-port: 7890\n", "\n", newline)
		for _, ops := range []string{
			`[{"op":"replace","index":1,"rule":"MATCH,REJECT"}]`,
			`[{"op":"delete","index":1}]`,
			`[{"op":"insert","index":1,"rule":"DOMAIN,b.example,REJECT"}]`,
			`[{"op":"move","index":0,"to":1}]`,
			`[{"op":"replace","index":0,"rule":"DOMAIN,c.example,REJECT"}]`,
		} {
			edited, err := EditRulesForIOS(source, ops)
			if err != nil {
				t.Fatalf("%q %s: %v", newline, ops, err)
			}
			if !strings.Contains(edited.Text, "# keep me") || !strings.Contains(edited.Text, "# about the last") || !strings.Contains(edited.Text, "mixed-port: 7890") {
				t.Errorf("%q %s: lost what follows:\n%s", newline, ops, edited.Text)
			}
			var document struct {
				Rules []string `yaml:"rules"`
			}
			if err := yaml.Unmarshal([]byte(edited.Text), &document); err != nil || len(document.Rules) != int(edited.Total) {
				t.Errorf("%q %s: %v\n%s", newline, ops, err, edited.Text)
			}
		}
	}
}
