package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func normalizeFixture(t *testing.T, yaml string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	return raw
}

func nePolicy() appleRuntimePolicy {
	return runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
}

func TestNormalizeReportsButKeepsAnUnroutableDNSFragment(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
proxies:
  - {name: Known, type: direct}
dns:
  enable: true
  nameserver:
    - "https://1.1.1.1/dns-query#Ghost"
rules:
  - MATCH,DIRECT
`)
	reported := detectUnroutableDNSFragments(raw)
	if len(reported) == 0 {
		t.Fatal("a fragment naming an undefined proxy must be reported")
	}
	if !strings.Contains(strings.Join(raw.DNS.NameServer, "|"), "Ghost") {
		t.Fatal("the fragment must be kept verbatim; stripping it would reroute DNS silently")
	}

	fine := normalizeFixture(t, `
mode: rule
proxies:
  - {name: Known, type: direct}
dns:
  enable: true
  nameserver:
    - "https://1.1.1.1/dns-query#Known"
rules:
  - MATCH,DIRECT
`)
	if reported := detectUnroutableDNSFragments(fine); len(reported) != 0 {
		t.Fatalf("a fragment naming a defined proxy must not be reported: %v", reported)
	}
}

func TestUnroutableDNSFragmentDiagnosticQuotesTheEntry(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
proxies:
  - {name: Known, type: direct}
dns:
  enable: true
  nameserver:
    - "https://user:s3cr3tPass@doh.example.com/dns-query?token=SECRETTOKEN#Ghost"
    - "https://dns.nextdns.io/abc123profile#Ghost"
rules:
  - MATCH,DIRECT
`)
	reported := detectUnroutableDNSFragments(raw)
	if len(reported) == 0 {
		t.Fatal("a fragment naming an undefined proxy must still be reported")
	}
	joined := strings.Join(reported, "\n")
	for _, part := range []string{"doh.example.com", "Ghost", "s3cr3tPass", "SECRETTOKEN", "abc123profile"} {
		if !strings.Contains(joined, part) {
			t.Fatalf("the diagnostic dropped %q; it must quote the entry as written:\n%s", part, joined)
		}
	}
	if !strings.Contains(strings.Join(raw.DNS.NameServer, "|"), "s3cr3tPass") {
		t.Fatal("the nameserver must stay verbatim in the config")
	}
}

func TestNormalizeKeepsOwnerMetadataRulesInOrder(t *testing.T) {
	source := `
mode: rule
rules:
  - DOMAIN,first.example,DIRECT
  - PROCESS-NAME,Mail,DIRECT
  - DOMAIN,second.example,DIRECT
  - UID,501,DIRECT
  - DOMAIN,third.example,DIRECT
`
	raw := normalizeFixture(t, source)

	want := []string{
		"DOMAIN,first.example,DIRECT", "PROCESS-NAME,Mail,DIRECT",
		"DOMAIN,second.example,DIRECT", "UID,501,DIRECT", "DOMAIN,third.example,DIRECT",
	}
	if len(raw.Rule) != len(want) {
		t.Fatalf("kept %d rules, want all %d: %v", len(raw.Rule), len(want), raw.Rule)
	}
	for index, rule := range want {
		if raw.Rule[index] != rule {
			t.Fatalf("rule %d = %q, want %q -- nothing is removed and order must survive", index, raw.Rule[index], rule)
		}
	}
	if summaries := summarizeMetadataRuleOccurrences(raw, nePolicy().processMetadata()); len(summaries) == 0 {
		t.Fatal("the kept metadata rules must still be reported")
	}
}

func TestNormalizeKeepsMetadataRulesInsideInlineRuleProviders(t *testing.T) {
	raw := normalizeFixture(t, `
mode: rule
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,keep.example
      - PROCESS-NAME,Mail
rules:
  - RULE-SET,inline,DIRECT
  - MATCH,DIRECT
`)
	rendered := strings.Join(inlineProviderPayloadStrings(t, raw, "inline"), "|")
	if !strings.Contains(rendered, "PROCESS-NAME") {
		t.Fatalf("the metadata rule was removed from the inline payload: %s", rendered)
	}
	if !strings.Contains(rendered, "keep.example") {
		t.Fatalf("an executable rule was lost from the inline payload: %s", rendered)
	}
	if occurrences := inlineRuleProviderMetadataOccurrences(raw, nePolicy().processMetadata()); len(occurrences) != 1 {
		t.Fatalf("the inline payload entry must be reported once, got %d", len(occurrences))
	}
}

func TestNormalizeLeavesTheSameConfigurationHoweverItWalksIt(t *testing.T) {
	source := `
mode: rule
proxies:
  - {name: Known, type: direct, interface-name: en0, routing-mark: 233}
dns:
  enable: true
  nameserver:
    - system://
    - 8.8.8.8
    - "https://1.1.1.1/dns-query#Ghost"
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,inline-keep.example
      - UID,501
rules:
  - DOMAIN,first.example,DIRECT
  - PROCESS-NAME,Mail,DIRECT
  - MATCH,DIRECT
`
	raw := normalizeFixture(t, source)
	normalizeRawConfigForApple(raw, nePolicy())

	if joined := strings.Join(raw.DNS.NameServer, "|"); strings.Contains(joined, "system://") {
		t.Fatalf("a system resolver reaches only the tunnel's own DNS address, which mihomo blacklists, so it must go: %s", joined)
	}
	if joined := strings.Join(raw.DNS.NameServer, "|"); !strings.Contains(joined, "Ghost") {
		t.Fatalf("an unroutable fragment must be kept verbatim: %s", joined)
	}
	if len(raw.DNS.NameServer) == 0 {
		t.Fatal("an emptied bootstrap must be refilled, not left empty")
	}
	var sawProcessRule bool
	for _, rule := range raw.Rule {
		if strings.HasPrefix(rule, "PROCESS-NAME") {
			sawProcessRule = true
		}
	}
	if !sawProcessRule {
		t.Fatal("an owner-metadata rule was removed from the main rules block; they are kept and reported now")
	}
	if rendered := strings.Join(inlineProviderPayloadStrings(t, raw, "inline"), "|"); strings.Contains(rendered, "UID,") {
		t.Fatalf("UID survived in the inline payload: %s", rendered)
	}
	if len(raw.Proxy) != 1 {
		t.Fatalf("the proxy must survive, got %d", len(raw.Proxy))
	}
	for _, field := range []string{"interface-name", "routing-mark"} {
		if _, present := raw.Proxy[0][field]; !present {
			t.Fatalf("%s was removed from the proxy; upstream ignores it under the socket hook, so it is kept", field)
		}
	}
}

func inlineProviderPayloadStrings(t *testing.T, raw *config.RawConfig, name string) []string {
	t.Helper()
	definition, exists := raw.RuleProvider[name]
	if !exists {
		t.Fatalf("rule provider %q is missing", name)
	}
	entries, _ := definition["payload"].([]any)
	rendered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if text, ok := entry.(string); ok {
			rendered = append(rendered, text)
		}
	}
	return rendered
}
