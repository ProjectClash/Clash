package clash

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

var dnsFieldClassification = map[string]string{
	"nameserver":                      "resolver",
	"fallback":                        "resolver",
	"proxy-server-nameserver":         "resolver",
	"direct-nameserver":               "resolver",
	"nameserver-policy":               "resolver",
	"proxy-server-nameserver-policy":  "resolver",
	"default-nameserver":              "bootstrap",
	"enable":                          "not-a-resolver",
	"prefer-h3":                       "not-a-resolver",
	"ipv6":                            "not-a-resolver",
	"ipv6-timeout":                    "not-a-resolver",
	"use-hosts":                       "not-a-resolver",
	"use-system-hosts":                "not-a-resolver",
	"respect-rules":                   "not-a-resolver",
	"fallback-filter":                 "not-a-resolver",
	"fallback-lazy-query":             "not-a-resolver",
	"listen":                          "not-a-resolver",
	"listen-routing-mark":             "not-a-resolver",
	"enhanced-mode":                   "not-a-resolver",
	"fake-ip-range":                   "not-a-resolver",
	"fake-ip-range6":                  "not-a-resolver",
	"fake-ip-filter":                  "not-a-resolver",
	"fake-ip-filter-mode":             "not-a-resolver",
	"fake-ip-ttl":                     "not-a-resolver",
	"cache-algorithm":                 "not-a-resolver",
	"cache-max-size":                  "not-a-resolver",
	"direct-nameserver-follow-policy": "not-a-resolver",
}

func rawDNSYAMLKeys(t *testing.T) []string {
	t.Helper()
	typ := reflect.TypeOf(config.RawDNS{})
	keys := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		keys = append(keys, strings.Split(tag, ",")[0])
	}
	if len(keys) == 0 {
		t.Fatal("reflected no yaml keys off config.RawDNS; the derivation is wrong, not the classification")
	}
	return keys
}

func TestEveryDNSResolverFieldIsClassified(t *testing.T) {
	upstream := rawDNSYAMLKeys(t)
	seen := map[string]bool{}
	for _, key := range upstream {
		seen[key] = true
		kind, ok := dnsFieldClassification[key]
		if !ok {
			t.Errorf("upstream's dns.%s is not classified. If it holds resolvers, add it to "+
				"dnsResolverFields AND to repairApplePacketTunnelDNS so system/dhcp is stripped "+
				"there too; if it does not, record it here as not-a-resolver.", key)
			continue
		}
		if kind == "resolver" && !contains(dnsResolverFields, key) {
			t.Errorf("dns.%s is classified as a resolver field but is missing from dnsResolverFields", key)
		}
	}
	for key := range dnsFieldClassification {
		if !seen[key] {
			t.Errorf("dns.%s is classified here but upstream's RawDNS no longer declares it; drop the entry", key)
		}
	}
	for _, key := range dnsResolverFields {
		if dnsFieldClassification[key] != "resolver" {
			t.Errorf("dnsResolverFields lists dns.%s, which is classified %q", key, dnsFieldClassification[key])
		}
	}
	if dnsFieldClassification["default-nameserver"] != "bootstrap" {
		t.Error("default-nameserver must stay classified as the bootstrap; defaultNameserverStrip is the only judge it has")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func TestNonResolverDNSFieldsAreNotJudgedAsResolvers(t *testing.T) {
	for _, tc := range []struct{ name, what, yaml string }{
		{
			name: "fake-ip-filter entry named system",
			what: "a fake-ip-filter domain entry",
			yaml: `
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: ['223.5.5.5']
  fake-ip-filter: ['system', '+.lan']
`,
		},
		{
			name: "fallback-filter domain starting with system:",
			what: "a fallback-filter domain",
			yaml: `
dns:
  enable: true
  nameserver: ['223.5.5.5']
  fallback: ['8.8.8.8']
  fallback-filter:
    geoip: true
    domain: ['system:8080']
`,
		},
		{
			name: "dns.listen literally system",
			what: "the dns listen address",
			yaml: `
dns:
  enable: true
  nameserver: ['223.5.5.5']
  listen: 'system'
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustNotRefuse(t, planOf(t, tc.yaml), tc.what)
		})
	}
}

func TestSystemResolverInARealFieldIsStillANotice(t *testing.T) {
	r := planOf(t, `
dns:
  enable: true
  nameserver: ['system', '223.5.5.5']
  fallback: ['dhcp://en0']
`)
	mustNotRefuse(t, r, "a system nameserver")
}
