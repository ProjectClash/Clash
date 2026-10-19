package config

import (
	"strings"
	"testing"
)

const ssidNameserversHead = "dns:\n  enable: true\n  nameserver: [1.1.1.1]\n"

func TestSSIDNameserversParseAsNameserverPolicyDoes(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(ssidNameserversHead + "  x-clash-ssid-nameservers:\n    \"LOON's WIFI\": system\n    Office: [https://dns.example/dns-query, 9.9.9.9]\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	policies := cfg.DNS.SSIDPolicy
	if len(policies) != 2 || policies[0].SSID != "LOON's WIFI" || policies[1].SSID != "Office" {
		t.Fatalf("parsed %+v", policies)
	}
	if n := len(policies[0].NameServers); n != 1 || policies[0].NameServers[0].Net != "system" {
		t.Fatalf("server:system parsed as %+v", policies[0].NameServers)
	}
	if n := len(policies[1].NameServers); n != 2 {
		t.Fatalf("Office has %d nameservers, want 2", n)
	}
}

func TestSSIDNameserversRefuseAnEntryWithNoServer(t *testing.T) {
	for _, entry := range []string{"    Home: []\n", "    \"\": [1.1.1.1]\n", "    \"  \": [1.1.1.1]\n"} {
		raw, err := UnmarshalRawConfig([]byte(ssidNameserversHead + "  x-clash-ssid-nameservers:\n" + entry))
		if err != nil {
			t.Fatalf("%q does not unmarshal: %v", entry, err)
		}
		if _, err := ParseRawConfig(raw); err == nil || !strings.Contains(err.Error(), "x-clash-ssid-nameservers") {
			t.Errorf("%q: %v", entry, err)
		}
	}
}
