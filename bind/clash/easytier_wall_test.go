package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/constant/features"
)

const easyTierWallDocument = `
mixed-port: 7890
dns:
  enable: true
  nameserver:
    - et://office-mesh
    - 8.8.8.8
  fallback:
    - easytier://office-mesh
    - 1.1.1.1
  fallback-filter:
    geoip: false
  proxy-server-nameserver:
    - et://office-mesh
    - 9.9.9.9
  direct-nameserver:
    - et://office-mesh
    - 223.5.5.5
  nameserver-policy:
    "+.corp.example": et://office-mesh
    "+.lab.example":
      - et://office-mesh
      - 8.8.4.4
proxies:
  - name: plain
    type: socks5
    server: 198.51.100.7
    port: 1080
  - name: office-mesh
    type: easytier
    network-name: office
    network-secret: hunter2
    peers:
      - tcp://203.0.113.10:11010
proxy-groups:
  - name: Office
    type: select
    proxies:
      - office-mesh
      - plain
rules:
  - DOMAIN-SUFFIX,corp.example,office-mesh
  - MATCH,Office
`

func TestEasyTierNodeIsReportedAsAPlaceholderOnMobileProfiles(t *testing.T) {
	for _, seat := range []struct {
		name    string
		profile runtimeProfile
		walled  bool
	}{
		{"ios", runtimeProfileIOSPacketTunnel, true},
		{"tvos", runtimeProfileTVOSPacketTunnel, true},
		{"macos-tunnel", runtimeProfileMacOSPacketTunnel, false},
		{"macos-app", runtimeProfileMacOSApplication, false},
	} {
		t.Run(seat.name, func(t *testing.T) {
			rows, err := collectConfigDeviations(easyTierWallDocument, runtimePolicyFor(seat.profile, seat.profile != runtimeProfileMacOSApplication))
			if err != nil {
				t.Fatal(err)
			}
			var found *configDeviation
			for i := range rows {
				if rows[i].Field == "proxies" && strings.Contains(rows[i].Given, "proxies[1]") {
					found = &rows[i]
				}
			}
			if !seat.walled {
				if found != nil {
					t.Fatalf("%s honours EasyTier and must not report the node: %+v", seat.name, *found)
				}
				return
			}
			if found == nil {
				t.Fatalf("no proxies row for proxies[1] on %s: %v", seat.name, fieldsOf(rows))
			}
			if found.Category != deviationForced || !found.Written || found.RuleKind != "" {
				t.Fatalf("row shape: %+v", *found)
			}
			if !strings.Contains(found.Given, "office-mesh") || !strings.Contains(found.Effective, "reject placeholder") {
				t.Fatalf("row does not name the node and the placeholder: %+v", *found)
			}
			if found.Alternative == "" {
				t.Fatalf("the row must say where the node does work: %+v", *found)
			}
		})
	}
}

func TestEasyTierNameserversAreStrippedOnMobileProfiles(t *testing.T) {
	for _, seat := range []struct {
		name    string
		profile runtimeProfile
		walled  bool
	}{
		{"ios", runtimeProfileIOSPacketTunnel, true},
		{"macos-tunnel", runtimeProfileMacOSPacketTunnel, false},
	} {
		t.Run(seat.name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(easyTierWallDocument))
			if err != nil {
				t.Fatal(err)
			}
			normalizeRawConfigForApple(raw, runtimePolicyFor(seat.profile, true))
			lists := map[string][]string{
				"nameserver":              raw.DNS.NameServer,
				"fallback":                raw.DNS.Fallback,
				"proxy-server-nameserver": raw.DNS.ProxyServerNameserver,
				"direct-nameserver":       raw.DNS.DirectNameServer,
			}
			for field, list := range lists {
				hasEasyTier := false
				for _, ns := range list {
					if isEasyTierNameserver(ns) {
						hasEasyTier = true
					}
				}
				if hasEasyTier == seat.walled {
					t.Errorf("%s: %s = %v (walled=%v)", seat.name, field, list, seat.walled)
				}
				if len(list) == 0 {
					t.Errorf("%s: %s lost its remaining resolver: %v", seat.name, field, list)
				}
			}
			corp := dnsServerStrings(policyValue(t, raw, "+.corp.example"))
			lab := dnsServerStrings(policyValue(t, raw, "+.lab.example"))
			if seat.walled {
				if len(corp) != 1 || corp[0] != "rcode://name_error" {
					t.Errorf("a policy whose only resolver was the node fails closed, got %v", corp)
				}
				if len(lab) != 1 || lab[0] != "8.8.4.4" {
					t.Errorf("a policy keeps its other resolver, got %v", lab)
				}
			} else if len(corp) != 1 || corp[0] != "et://office-mesh" || len(lab) != 2 {
				t.Errorf("macOS must leave the policies as written: %v %v", corp, lab)
			}
		})
	}
}

func policyValue(t *testing.T, raw *config.RawConfig, key string) any {
	t.Helper()
	value, ok := raw.DNS.NameServerPolicy.Get(key)
	if !ok {
		t.Fatalf("nameserver-policy lost %q", key)
	}
	return value
}

func TestEasyTierDocumentParsesWholeOnTheMobileProfile(t *testing.T) {
	setupConfigPipelineTest(t)
	parsed, err := parseConfigForIOS(easyTierWallDocument, true)
	if err != nil {
		t.Fatalf("the document must parse on the mobile profile in every build: %v", err)
	}
	node, ok := parsed.Proxies["office-mesh"]
	if !ok {
		t.Fatalf("the node kept its name; proxies = %v", proxyNames(parsed))
	}
	if features.NoEasyTier {
		if node.Type().String() != "Reject" {
			t.Fatalf("no_easytier build: node type = %s, want Reject", node.Type())
		}
	} else if node.Type().String() != "EasyTier" {
		t.Fatalf("ordinary build: node type = %s, want EasyTier", node.Type())
	}
	group, ok := parsed.Proxies["Office"]
	if !ok {
		t.Fatalf("the group that names the node is gone; proxies = %v", proxyNames(parsed))
	}
	if group.Type().String() != "Selector" {
		t.Fatalf("group type = %s", group.Type())
	}
	for _, proxy := range parsed.Proxies {
		_ = proxy.Close()
	}
}

func proxyNames(parsed *config.Config) []string {
	names := make([]string, 0, len(parsed.Proxies))
	for name := range parsed.Proxies {
		names = append(names, name)
	}
	return names
}
