package clash

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
)

func decodeDNSQuery(t *testing.T, payload string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("the export must always return JSON, got %q: %v", payload, err)
	}
	return decoded
}

func TestDNSQueryJSONReportsFailuresAsJSON(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })

	resolver.DefaultResolver = nil
	for name, args := range map[string][2]string{
		"no resolver": {"example.com", "A"},
	} {
		decoded := decodeDNSQuery(t, DNSQueryJSON(args[0], args[1]))
		if _, ok := decoded["error"]; !ok {
			t.Fatalf("%s must report an error key, got %v", name, decoded)
		}
	}

	for _, args := range [][2]string{
		{"", "A"},
		{"   ", "A"},
		{"example.com", "INVALID_TYPE"},
	} {
		decoded := decodeDNSQuery(t, DNSQueryJSON(args[0], args[1]))
		message, ok := decoded["error"].(string)
		if !ok || message == "" {
			t.Fatalf("name=%q type=%q must report an error, got %v", args[0], args[1], decoded)
		}
	}
}

func TestDNSQueryJSONKeepsTheErrorVerbatim(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = nil

	decoded := decodeDNSQuery(t, DNSQueryJSON("nas.local", "A"))
	message, _ := decoded["error"].(string)
	if !strings.Contains(message, "DNS section is disabled") {
		t.Fatalf("the message must say what happened, got %q", message)
	}
}

func TestDNSQueryJSONDefaultsToA(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = nil

	decoded := decodeDNSQuery(t, DNSQueryJSON("example.com", ""))
	message, _ := decoded["error"].(string)
	if strings.Contains(message, "invalid query type") {
		t.Fatal("an omitted type must default to A rather than be refused")
	}
}

func TestDNSQueryJSONAcceptsLowercaseTypes(t *testing.T) {
	previous := resolver.DefaultResolver
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	resolver.DefaultResolver = nil

	for _, qType := range []string{"aaaa", "AAAA", "ptr", "SRV", "txt"} {
		decoded := decodeDNSQuery(t, DNSQueryJSON("example.com", qType))
		message, _ := decoded["error"].(string)
		if strings.Contains(message, "invalid query type") {
			t.Fatalf("type %q must be accepted", qType)
		}
	}
}
