package clash

import (
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestProxyImportCarriesDNSNameServerPolicy(t *testing.T) {
	payload := []byte(`
proxies:
  - name: n1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: x
dns:
  enable: true
  nameserver:
    - 8.8.8.8
  nameserver-policy:
    "geosite:cn": 223.5.5.5
    "+.example.com": 1.1.1.1
  proxy-server-nameserver-policy:
    "geosite:private": DIRECT
`)
	report, err := proxyImportReportOf(payload, "subscriptionBody", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(report.Proxies))
	}
	if report.DNSNameServerPolicy == nil {
		t.Fatalf("expected nameserver-policy to be extracted")
	}
	if got := report.DNSNameServerPolicy["+.example.com"]; got != "1.1.1.1" {
		t.Fatalf("expected +.example.com -> 1.1.1.1, got %v", got)
	}
	if got := report.DNSNameServerPolicy["geosite:cn"]; got != "223.5.5.5" {
		t.Fatalf("expected geosite:cn -> 223.5.5.5, got %v", got)
	}
	if report.DNSProxyServerNameserverPolicy == nil {
		t.Fatalf("expected proxy-server-nameserver-policy to be extracted")
	}
	if got := report.DNSProxyServerNameserverPolicy["geosite:private"]; got != "DIRECT" {
		t.Fatalf("expected geosite:private -> DIRECT, got %v", got)
	}
}

func TestProxyImportWithoutDNSLeavesPolicyNil(t *testing.T) {
	payload := []byte(`
proxies:
  - name: n1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: x
`)
	report, err := proxyImportReportOf(payload, "subscriptionBody", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.DNSNameServerPolicy != nil {
		t.Fatalf("expected nil nameserver-policy, got %v", report.DNSNameServerPolicy)
	}
	if report.DNSProxyServerNameserverPolicy != nil {
		t.Fatalf("expected nil proxy-server-nameserver-policy, got %v", report.DNSProxyServerNameserverPolicy)
	}
}

func TestProxyImportCarriesDNSNameServerPolicyFromJSONContainer(t *testing.T) {
	payload := []byte(`{
  "proxies": [
    {"name": "n1", "type": "ss", "server": "1.2.3.4", "port": 8388,
     "cipher": "aes-256-gcm", "password": "x"}
  ],
  "dns": {
    "enable": true,
    "nameserver": ["8.8.8.8"],
    "nameserver-policy": {"+.json.example.com": "1.0.0.1"}
  }
}`)
	report, err := proxyImportReportOf(payload, "subscriptionBody", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(report.Proxies))
	}
	if report.DNSNameServerPolicy == nil {
		t.Fatalf("expected nameserver-policy extracted from a JSON configuration container")
	}
	if got := report.DNSNameServerPolicy["+.json.example.com"]; got != "1.0.0.1" {
		t.Fatalf("expected +.json.example.com -> 1.0.0.1, got %v", got)
	}
	if report.DNSProxyServerNameserverPolicy != nil {
		t.Fatalf("expected no proxy-server-nameserver-policy, got %v", report.DNSProxyServerNameserverPolicy)
	}
}

// TestProxyImportDNSMergesUnderUserOverride proves the end-to-end contract the feature
// relies on: the airport's nameserver-policy is appended into the node document, and when
// the user's main config (carried as an override patch) also declares a nameserver-policy,
// the maps union with the user's entries winning on conflicts.
func TestProxyImportDNSMergesUnderUserOverride(t *testing.T) {
	report, err := proxyImportReportOf([]byte(`
proxies:
  - name: n1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: x
dns:
  nameserver-policy:
    "+.airport.com": 1.1.1.1
    "geosite:cn": 223.5.5.5
`), "subscriptionBody", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.DNSNameServerPolicy == nil {
		t.Fatalf("expected nameserver-policy extracted")
	}

	nodeDoc := map[string]any{
		"proxies": []any{map[string]any{"name": "n1"}},
		"dns":     map[string]any{"nameserver-policy": report.DNSNameServerPolicy},
	}
	rawYAML, err := yaml.Marshal(nodeDoc)
	if err != nil {
		t.Fatalf("marshal node doc: %v", err)
	}

	// User's main config: its own nameserver-policy, which must win on shared keys.
	overrideJSON := `{"patch":{"dns":{"enable":true,"nameserver":["8.8.8.8"],"nameserver-policy":{"geosite:cn":"119.29.29.29","+.user.com":"9.9.9.9"}}}}`
	merged, err := mergeOverrideDocument(string(rawYAML), nil, overrideJSON)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	var root map[string]any
	if err := yaml.Unmarshal([]byte(merged.text), &root); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	dns, ok := root["dns"].(map[string]any)
	if !ok {
		t.Fatalf("merged dns is not a mapping: %v", root["dns"])
	}
	policy, ok := dns["nameserver-policy"].(map[string]any)
	if !ok {
		t.Fatalf("merged nameserver-policy is not a mapping: %v", dns["nameserver-policy"])
	}

	if policy["+.airport.com"] != "1.1.1.1" {
		t.Fatalf("airport-only entry lost: %v", policy)
	}
	if policy["geosite:cn"] != "119.29.29.29" {
		t.Fatalf("user override did not win on geosite:cn: %v", policy)
	}
	if policy["+.user.com"] != "9.9.9.9" {
		t.Fatalf("user-only entry lost: %v", policy)
	}
}
