package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestNormalizeStripsPolicyNameserversAndFragments(t *testing.T) {
	content := `
dns:
  enable: true
  nameserver: ["https://1.1.1.1/dns-query#en0&h3=true"]
  nameserver-policy:
    "example.com": system
    "multi.example.com": [system, 223.5.5.5]
    "keep.example.com": 8.8.8.8
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080}
`
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForIOS(raw, true)

	if got := raw.DNS.NameServer[0]; got != "https://1.1.1.1/dns-query#en0&h3=true" {
		t.Fatalf("unroutable fragment must be kept as-is: %q", got)
	}
	value, present := raw.DNS.NameServerPolicy.Get("example.com")
	if !present {
		t.Fatal("all-system policy key must fail closed, not be removed")
	}
	if servers := dnsServerStrings(value); len(servers) != 1 || servers[0] != "rcode://name_error" {
		t.Fatalf("all-system policy must resolve NXDOMAIN (fail closed): %v", servers)
	}
	value, present = raw.DNS.NameServerPolicy.Get("multi.example.com")
	if !present {
		t.Fatal("mixed policy key must survive")
	}
	servers := dnsServerStrings(value)
	if len(servers) != 1 || servers[0] != "223.5.5.5" {
		t.Fatalf("mixed policy not filtered to explicit resolver: %v", servers)
	}
	if _, present := raw.DNS.NameServerPolicy.Get("keep.example.com"); !present {
		t.Fatal("clean policy key must be untouched")
	}
}

func TestNormalizeKeepsFragmentNamingConfiguredProxy(t *testing.T) {
	content := `
dns:
  enable: true
  nameserver: ["https://1.1.1.1/dns-query#node"]
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080}
`
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForIOS(raw, true)
	if got := raw.DNS.NameServer[0]; got != "https://1.1.1.1/dns-query#node" {
		t.Fatalf("fragment naming a configured proxy must be kept (DNS-via-proxy works on iOS): %q", got)
	}
}

func TestCheckConfigStartsPolicySystemAndFragmentEdges(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	const edges = `
mode: rule
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ["https://1.1.1.1/dns-query#en0", 223.5.5.5]
  nameserver-policy:
    "example.com": system
proxies:
  - {name: p, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
`
	if err := CheckConfig(edges); err != nil {
		t.Fatalf("policy-system + interface-fragment config must start on iOS (tolerate + strip), got: %v", err)
	}
}

func TestPlanNotesPolicySystemAndFragmentAsStripped(t *testing.T) {
	r := planOf(t, `
dns:
  nameserver: ["https://1.1.1.1/dns-query#en0"]
  nameserver-policy:
    "example.com": system
`)
	if len(r.Errors) != 0 {
		t.Fatalf("stripped DNS policy/fragment must not be a plan error: %+v", r.Errors)
	}
	var policyNoted, fragmentNoted bool
	for _, n := range r.Notices {
		if strings.Contains(n, "nameserver-policy") && strings.Contains(n, "system") {
			policyNoted = true
		}
		if strings.Contains(n, "fragment") {
			fragmentNoted = true
		}
	}
	if !policyNoted || !fragmentNoted {
		t.Fatalf("expected policy+fragment stripped notices, got: %v", r.Notices)
	}
}
