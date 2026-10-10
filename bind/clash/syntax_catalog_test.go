package clash

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	P "github.com/ProjectClash/Clash/constant/provider"
)

func upstreamSource(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile("../../" + path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func quotedCases(t *testing.T, source, function string) []string {
	t.Helper()
	start := strings.Index(source, "func "+function)
	if start < 0 {
		t.Fatalf("no func %s", function)
	}
	body := source[start:]
	if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
		body = body[:end+1]
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "case ") {
			continue
		}
		for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(trimmed, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func mustCatalog(t *testing.T, profile string) syntaxCatalog {
	t.Helper()
	box, err := SyntaxCatalogForIOS(profile)
	if err != nil {
		t.Fatal(err)
	}
	var catalog syntaxCatalog
	if err := json.Unmarshal([]byte(box.Value), &catalog); err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestSyntaxCatalogRuleKindsAreTheParsersCases(t *testing.T) {
	want := quotedCases(t, upstreamSource(t, "rules/parser.go"), "ParseRule(")
	var got []string
	for _, kind := range mustCatalog(t, "").RuleKinds {
		got = append(got, kind.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule kinds drifted from rules/parser.go:\n got  %v\n want %v", got, want)
	}
	source := upstreamSource(t, "rules/parser.go")
	takes := map[string]bool{}
	var pending []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "case ") {
			pending = pending[:0]
			for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(trimmed, -1) {
				pending = append(pending, m[1])
			}
		} else if strings.Contains(trimmed, "ParseParams(params)") {
			for _, name := range pending {
				takes[name] = true
			}
		}
	}
	for _, kind := range mustCatalog(t, "").RuleKinds {
		if (len(kind.Options) > 0) != takes[kind.Name] {
			t.Errorf("%s: options %v, parser reads params: %v", kind.Name, kind.Options, takes[kind.Name])
		}
	}
}

func TestSyntaxCatalogGroupsAndEnumsAreTheCoresOwn(t *testing.T) {
	catalog := mustCatalog(t, "")
	groupSource := upstreamSource(t, "adapter/outboundgroup/parser.go")
	var wantTypes []string
	for _, name := range quotedCases(t, groupSource, "ParseProxyGroup(") {
		if name != "relay" {
			wantTypes = append(wantTypes, name)
		}
	}
	var gotTypes []string
	for _, group := range catalog.GroupTypes {
		gotTypes = append(gotTypes, group.Name)
		for _, field := range []string{"name", "type", "proxies", "use", "filter", "hidden"} {
			if !contains(group.Fields, field) {
				t.Errorf("%s lacks common field %s", group.Name, field)
			}
		}
	}
	if !reflect.DeepEqual(sortedCopy(gotTypes), sortedCopy(wantTypes)) {
		t.Fatalf("group types %v, parser cases %v", gotTypes, wantTypes)
	}
	for _, group := range catalog.GroupTypes {
		switch group.Name {
		case "url-test":
			if !contains(group.Fields, "tolerance") {
				t.Errorf("url-test lacks tolerance: %v", group.Fields)
			}
		case "select":
			if !contains(group.Fields, "default-selected") {
				t.Errorf("select lacks default-selected: %v", group.Fields)
			}
		case "load-balance":
			want := quotedCases(t, upstreamSource(t, "adapter/outboundgroup/loadbalance.go"), "NewLoadBalance(")
			var nonEmpty []string
			for _, w := range want {
				if w != "" {
					nonEmpty = append(nonEmpty, w)
				}
			}
			if !reflect.DeepEqual(group.Enums["strategy"], nonEmpty) {
				t.Errorf("load-balance strategies %v, source %v", group.Enums["strategy"], nonEmpty)
			}
		}
	}

	providerSource := upstreamSource(t, "rules/provider/parse.go")
	if got, want := catalog.RuleProvider.Types, quotedCases(t, providerSource, "ParseRuleProvider("); !reflect.DeepEqual(sortedCopy(got), sortedCopy(want)) {
		t.Errorf("rule-provider types %v, parser %v", got, want)
	}
	var tags []string
	for _, m := range regexp.MustCompile(`provider:"([^",]+)`).FindAllStringSubmatch(providerSource, -1) {
		tags = append(tags, m[1])
	}
	if !reflect.DeepEqual(catalog.RuleProvider.Fields, tags) {
		t.Errorf("rule-provider fields %v, schema tags %v", catalog.RuleProvider.Fields, tags)
	}
	for _, behavior := range catalog.RuleProvider.Behaviors {
		if _, err := P.ParseBehavior(behavior); err != nil {
			t.Errorf("behavior %s: %v", behavior, err)
		}
	}
	for _, format := range catalog.RuleProvider.Formats {
		if _, err := P.ParseRuleFormat(format); err != nil {
			t.Errorf("format %s: %v", format, err)
		}
	}
	if want := []string{"TLS", "HTTP", "QUIC"}; !reflect.DeepEqual(catalog.SnifferProtocols, want) {
		t.Errorf("sniffer %v", catalog.SnifferProtocols)
	}
	if want := []string{"normal", "fake-ip", "redir-host"}; !reflect.DeepEqual(catalog.DNSEnhancedModes, want) {
		t.Errorf("enhanced modes %v", catalog.DNSEnhancedModes)
	}
}

func TestSyntaxCatalogPlatformKeysFollowTheProfile(t *testing.T) {
	ios := mustCatalog(t, RuntimeProfileIOSPacketTunnel)
	mac := mustCatalog(t, RuntimeProfileMacOSPacketTunnel)
	keys := func(c syntaxCatalog) map[string]syntaxPlatformKey {
		out := map[string]syntaxPlatformKey{}
		for _, k := range c.PlatformDecidedKeys {
			out[k.Path+"/"+k.RuleKind] = k
		}
		return out
	}
	iosKeys, macKeys := keys(ios), keys(mac)
	for _, path := range []string{"tun.auto-route/", "redir-port/", "tun.route-address-set/"} {
		if _, ok := iosKeys[path]; !ok {
			t.Errorf("iOS lacks %s", path)
		}
	}
	if k := iosKeys["tun.route-address-set/"]; !k.Honoured {
		t.Errorf("route-address-set not marked honoured: %+v", k)
	}
	if _, ok := iosKeys["rules/UID"]; !ok {
		t.Errorf("iOS lacks the UID rule entry")
	}
	if _, ok := macKeys["rules/UID"]; ok {
		t.Errorf("macOS resolves UID and must not list it")
	}
	if _, ok := iosKeys["proxies/"]; ok {
		t.Errorf("the EasyTier list scan is not a key")
	}
	matches := func(c syntaxCatalog, name string) bool {
		for _, k := range c.RuleKinds {
			if k.Name == name {
				return k.MatchesHere
			}
		}
		t.Fatalf("no %s", name)
		return false
	}
	if matches(ios, "PROCESS-NAME") || !matches(mac, "PROCESS-NAME") || !matches(ios, "DOMAIN") {
		t.Errorf("matchesHere: iOS PROCESS-NAME %v, macOS %v, iOS DOMAIN %v", matches(ios, "PROCESS-NAME"), matches(mac, "PROCESS-NAME"), matches(ios, "DOMAIN"))
	}
	if _, err := SyntaxCatalogForIOS("nonsense"); err == nil {
		t.Errorf("an unknown profile is refused")
	}
}

func TestSyntaxCatalogFieldsSayWhenThePlatformDecides(t *testing.T) {
	catalog := mustCatalog(t, RuntimeProfileIOSPacketTunnel)
	if catalog.SchemaVersion != 3 {
		t.Fatalf("schemaVersion %d", catalog.SchemaVersion)
	}
	byPath := map[string]syntaxField{}
	for _, field := range catalog.Fields {
		byPath[field.Path] = field
	}
	for path, want := range map[string]syntaxPlatformDecision{
		"tun.stack":             {When: "conditional", Condition: "includeAllNetworks", Category: deviationForced},
		"allow-lan":             {When: "conditional", Condition: "lanSharingOff", Category: deviationStripped},
		"profile.store-fake-ip": {When: "default", Value: "true", Category: deviationForced},
		"unified-delay":         {When: "default", Value: "true", Category: deviationForced},
		"dns.enable":            {When: "always", Value: "true", Category: deviationForced},
	} {
		got := byPath[path].PlatformDecision
		if got == nil || got.When != want.When || got.Condition != want.Condition || got.Category != want.Category ||
			(want.Value != "" && got.Value != want.Value) || got.Reason == "" || got.Effective == "" {
			t.Errorf("%s: %+v", path, got)
		}
	}
	for _, path := range []string{"tun.route-address-set", "tun.route-exclude-address-set", "profile.store-fake-ip", "unified-delay"} {
		if byPath[path].PlatformDecided {
			t.Errorf("%s: marked platformDecided", path)
		}
	}
	for _, path := range []string{"tun.route-address-set", "tun.route-exclude-address-set"} {
		if byPath[path].PlatformDecision != nil {
			t.Errorf("%s: decided %+v", path, byPath[path].PlatformDecision)
		}
	}
	rules := map[string]*deviationRule{}
	for i := range deviationRules {
		if !deviationRules[i].ruleScan {
			rules[deviationRules[i].field] = &deviationRules[i]
		}
	}
	for _, field := range catalog.Fields {
		rule, decision := rules[field.Path], field.PlatformDecision
		if rule == nil || decision == nil {
			continue
		}
		want := "always"
		switch {
		case rule.defaultOnly:
			want = "default"
		case rule.condition != "":
			want = "conditional"
		}
		if rule.honouredBy != "" || decision.When != want || decision.Value != rule.forcedValue {
			t.Errorf("%s: %+v for its rule (defaultOnly %v, condition %q, honouredBy %q, forced %q)",
				field.Path, decision, rule.defaultOnly, rule.condition, rule.honouredBy, rule.forcedValue)
		}
	}
	always := 0
	for _, field := range catalog.Fields {
		if decision := field.PlatformDecision; decision != nil {
			if !field.PlatformDecided && decision.When != "default" {
				t.Errorf("%s: a decision on a field not marked platformDecided", field.Path)
			}
			if decision.When == "always" {
				always++
				if decision.Condition != "" {
					t.Errorf("%s: always with a condition", field.Path)
				}
			}
		}
	}
	if always == 0 {
		t.Error("no field is decided always under the iOS packet tunnel")
	}
	mac := mustCatalog(t, RuntimeProfileMacOSApplication)
	for _, field := range mac.Fields {
		if (field.Path == "tun.stack" || field.Path == "allow-lan") && field.PlatformDecision != nil {
			t.Errorf("macOS App: %s decided: %+v", field.Path, field.PlatformDecision)
		}
	}
}

func TestSyntaxCatalogCarriesTheUnwrittenTunStackDefault(t *testing.T) {
	for _, on := range []bool{false, true} {
		withIncludeAllNetworks(t, on)
		catalog := mustCatalog(t, RuntimeProfileIOSPacketTunnel)
		var field *syntaxField
		for i := range catalog.Fields {
			if catalog.Fields[i].Path == "tun.stack" {
				field = &catalog.Fields[i]
			}
		}
		if field == nil || field.PlatformDecision == nil {
			t.Fatalf("IAN=%v: tun.stack has no platform decision", on)
		}
		decision := field.PlatformDecision
		if decision.When != "conditional" || decision.Condition != deviationConditionIncludeAllNetworks || decision.Unwritten != "gvisor" {
			t.Errorf("IAN=%v: decision %+v; want conditional on includeAllNetworks with unwritten gvisor", on, *decision)
		}
		var key *syntaxPlatformKey
		for i := range catalog.PlatformDecidedKeys {
			if catalog.PlatformDecidedKeys[i].Path == "tun.stack" {
				key = &catalog.PlatformDecidedKeys[i]
			}
		}
		if key == nil {
			t.Fatalf("IAN=%v: tun.stack is missing from the platform-decided keys", on)
		}
		if key.UpstreamDefault != "mips" || key.DefaultOnly == on {
			t.Errorf("IAN=%v: key %+v; want upstreamDefault mips and defaultOnly %v", on, *key, !on)
		}
	}
}
