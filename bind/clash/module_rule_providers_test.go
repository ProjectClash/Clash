package clash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

const sourceWithOwnRuleSet = "proxies:\n  - {name: P, type: direct}\n" +
	"rule-providers:\n  own: {type: file, behavior: domain, path: ./own.txt}\n" +
	"rules:\n  - RULE-SET,own,DIRECT\n  - DOMAIN,www.example.com,P\n  - MATCH,P\n"

var moduleSetsForTest = map[string]any{
	"module-a1b2c3d4-0000aaaa": map[string]any{"type": "file", "behavior": "domain", "path": "modules/m/sets/a.txt"},
	"module-a1b2c3d4-0000bbbb": map[string]any{"type": "http", "behavior": "classical", "url": "https://lists.example/b.list", "interval": 86400, "format": "text"},
}

var moduleSetRulesForTest = []string{"RULE-SET,module-a1b2c3d4-0000aaaa,REJECT", "RULE-SET,module-a1b2c3d4-0000bbbb,REJECT"}

func withModuleSetsHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	for _, path := range []string{"own.txt", "modules/m/sets/a.txt"} {
		full := filepath.Join(home, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("+.ads.example\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func ruleProvidersOf(t *testing.T, root map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	providers, _ := root["rule-providers"].(map[string]any)
	for name, raw := range providers {
		out[name], _ = raw.(map[string]any)
	}
	return out
}

func TestAModulesRuleSetsArePublishedBesideTheConfigurationsOwn(t *testing.T) {
	withModuleSetsHome(t)
	for name, resources := range map[string]map[string]any{
		"index":  indexResources(t.TempDir()),
		"inline": {"runtimeProfile": RuntimeProfileIOSPacketTunnel},
	} {
		answer, root := finalizeWithRulesBefore(t, sourceWithOwnRuleSet, resources, moduleSetRulesForTest, map[string]any{"ruleProviders": moduleSetsForTest})
		providers := ruleProvidersOf(t, root)
		if len(providers) != 3 {
			t.Fatalf("%s: published rule providers %v, want own and the module's two", name, providers)
		}
		if _, marked := providers["own"][moduleRuleProviderField]; marked {
			t.Errorf("%s: the configuration's own set carries the module mark", name)
		}
		for set := range moduleSetsForTest {
			if providers[set][moduleRuleProviderField] != true {
				t.Errorf("%s: %s is published without the module mark: %v", name, set, providers[set])
			}
		}
		refresh, _ := providers["module-a1b2c3d4-0000bbbb"][providerRefreshField].(map[string]any)
		if refresh["url"] != "https://lists.example/b.list" || refresh["interval"] != 86400 {
			t.Errorf("%s: the remote set is refreshed by %#v, want its url every 86400 s", name, refresh)
		}
		published, err := parseAfterLookups(answer.Text)
		if err != nil {
			t.Fatalf("%s: the tunnel cannot parse what was published: %v", name, err)
		}
		if len(published.RuleProviders) != 3 {
			t.Fatalf("%s: the tunnel reads %d rule providers, want 3", name, len(published.RuleProviders))
		}
		if first := published.RuleTable.At(0); first.RuleType() != C.RuleSet || first.Payload() != "module-a1b2c3d4-0000aaaa" {
			t.Fatalf("%s: the first rule is %s,%s; want the module's RULE-SET", name, first.RuleType(), first.Payload())
		}
	}
}

func TestAModulesRuleSetsArePublishedAgainAsThisPublishSays(t *testing.T) {
	withModuleSetsHome(t)
	resources := map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel}
	answer, _ := finalizeWithRulesBefore(t, sourceWithOwnRuleSet, resources, moduleSetRulesForTest, map[string]any{"ruleProviders": moduleSetsForTest})

	other := map[string]any{"module-ffff0000-0000cccc": map[string]any{"type": "file", "behavior": "domain", "path": "modules/m/sets/a.txt"}}
	_, again := finalizeWithRulesBefore(t, answer.Text, resources, []string{}, map[string]any{"ruleProviders": other})
	if providers := ruleProvidersOf(t, again); len(providers) != 2 || providers["own"] == nil || providers["module-ffff0000-0000cccc"] == nil {
		t.Fatalf("published again with other sets: %v", providers)
	}
	_, removed := finalizeWithRulesBefore(t, answer.Text, resources, []string{}, map[string]any{"ruleProviders": map[string]any{}})
	if providers := ruleProvidersOf(t, removed); len(providers) != 1 || providers["own"] == nil {
		t.Fatalf("published again with none: %v, want only the configuration's own", providers)
	}
	_, kept := finalizeWithRulesBefore(t, answer.Text, resources, nil, nil)
	if providers := ruleProvidersOf(t, kept); len(providers) != 3 {
		t.Fatalf("published again naming none: %v, want the earlier publish's kept", providers)
	}
}

func TestAModulesRuleSetIsRefusedWhereItWouldStandForTheConfigurationsOwn(t *testing.T) {
	withModuleSetsHome(t)
	resources := map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel}
	for name, tc := range map[string]struct {
		sets map[string]any
		want string
	}{
		"a name the configuration holds": {map[string]any{"own": map[string]any{"type": "file", "behavior": "domain", "path": "modules/m/sets/a.txt"}}, "ruleProviders[own]: the configuration has a rule provider of that name"},
		"not a definition":               {map[string]any{"module-x": "RULE-SET"}, "ruleProviders[module-x]: not a rule provider definition"},
		"no name":                        {map[string]any{" ": map[string]any{"type": "file"}}, "ruleProviders: a rule provider has no name"},
	} {
		_, err := finalizeWithRulesBeforeError(sourceWithOwnRuleSet, resources, nil, map[string]any{"ruleProviders": tc.sets})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestTheModuleMarkIsStrippedBeforeUpstreamParses(t *testing.T) {
	raw := &config.RawConfig{RuleProvider: map[string]map[string]any{"m": {"type": "file", moduleRuleProviderField: true}}}
	stripProviderSideUpdateMetadata(raw)
	if _, left := raw.RuleProvider["m"][moduleRuleProviderField]; left {
		t.Fatal("the module mark reached upstream's parse")
	}
}

func TestRuleProvidersOptionDecodes(t *testing.T) {
	for text, given := range map[string]bool{`{}`: false, `{"ruleProviders": null}`: false, `{"ruleProviders": {}}`: true} {
		var options finalizeOptions
		if err := json.Unmarshal([]byte(text), &options); err != nil {
			t.Fatal(err)
		}
		if (options.RuleProviders != nil) != given {
			t.Errorf("%s: given %v, want %v", text, options.RuleProviders != nil, given)
		}
	}
}

func TestARuleBeforeNamingASetThisPublishTookAwayIsRefused(t *testing.T) {
	withModuleSetsHome(t)
	resources := indexResources(t.TempDir())
	answer, _ := finalizeWithRulesBefore(t, sourceWithOwnRuleSet, resources, moduleSetRulesForTest, map[string]any{"ruleProviders": moduleSetsForTest})
	_, err := finalizeWithRulesBeforeError(answer.Text, resources, nil, map[string]any{"ruleProviders": map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "rule set [module-a1b2c3d4-0000aaaa] not found") {
		t.Fatalf("the rules before kept naming a set this publish took away: %v", err)
	}
}

func TestTheDocumentHandlePublishesAModulesRuleSets(t *testing.T) {
	withModuleSetsHome(t)
	handle, err := OpenDocumentForIOS(sourceWithOwnRuleSet)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	resources, _ := json.Marshal(map[string]any{"runtimeProfile": RuntimeProfileIOSPacketTunnel})
	options, _ := json.Marshal(map[string]any{"prependRules": moduleSetRulesForTest, "ruleProviders": moduleSetsForTest})
	box, err := handle.FinalizeWithOptions(string(resources), string(options))
	if err != nil {
		t.Fatal(err)
	}
	var answer finalizeOptionsAnswer
	if err := json.Unmarshal([]byte(box.Value), &answer); err != nil {
		t.Fatal(err)
	}
	published, err := parseAfterLookups(answer.Text)
	if err != nil || len(published.RuleProviders) != 3 {
		t.Fatalf("published through the handle: %v (%v)", published, err)
	}
	if text, _ := handle.Text(); strings.Contains(text.Value, "module-") {
		t.Fatal("the module's sets reached the reader's own document")
	}
}
