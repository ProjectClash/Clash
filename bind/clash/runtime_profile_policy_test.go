package clash

import (
	"reflect"
	"testing"

	"github.com/ProjectClash/Clash/component/process"
	"github.com/ProjectClash/Clash/config"
)

func TestAppleRuntimePolicyMatrix(t *testing.T) {
	tests := []struct {
		name                string
		profile             runtimeProfile
		underNE             bool
		wantNE              bool
		wantPacketTunnel    bool
		wantTrustedProcess  bool
		wantPacketTunnelDNS bool
		wantMemoryGeodata   bool
	}{
		{
			name: "iOS packet tunnel", profile: runtimeProfileIOSPacketTunnel, underNE: true,
			wantNE: true, wantPacketTunnel: true, wantPacketTunnelDNS: true, wantMemoryGeodata: true,
		},
		{
			name: "macOS packet tunnel", profile: runtimeProfileMacOSPacketTunnel, underNE: true,
			wantNE: true, wantPacketTunnel: true, wantPacketTunnelDNS: true,
		},
		{
			name: "macOS application", profile: runtimeProfileMacOSApplication, underNE: false,
			wantTrustedProcess: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := runtimePolicyFor(test.profile, test.underNE)
			if policy.networkExtension != test.wantNE ||
				policy.packetTunnel != test.wantPacketTunnel ||
				policy.trustedProcessMetadata != test.wantTrustedProcess ||
				policy.requirePacketTunnelDNS != test.wantPacketTunnelDNS ||
				policy.memoryConservativeGeodata != test.wantMemoryGeodata {
				t.Fatalf("runtimePolicyFor(%q, %v) = %+v", test.profile, test.underNE, policy)
			}
		})
	}
}

func TestMacOSProfilesPreserveStandardGeodataLoader(t *testing.T) {
	for _, profile := range []runtimeProfile{
		runtimeProfileMacOSPacketTunnel,
		runtimeProfileMacOSApplication,
	} {
		t.Run(profile.String(), func(t *testing.T) {
			policy := runtimePolicyFor(profile, profile != runtimeProfileMacOSApplication)
			raw := config.DefaultRawConfig()
			raw.GeodataLoader = "standard"
			normalizeRawConfigForApple(raw, policy)
			if raw.GeodataLoader != "standard" {
				t.Fatalf("raw geodata loader = %q, want standard", raw.GeodataLoader)
			}
			cfg := &config.Config{General: &config.General{GeodataLoader: "standard"}}
			overrideForAppleConfig(cfg, policy)
			if cfg.General.GeodataLoader != "standard" {
				t.Fatalf("parsed geodata loader = %q, want standard", cfg.General.GeodataLoader)
			}
		})
	}
}

func TestIOSProfileStillForcesMemoryConservativeGeodataLoader(t *testing.T) {
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	raw := config.DefaultRawConfig()
	raw.GeodataLoader = "standard"
	normalizeRawConfigForApple(raw, policy)
	if raw.GeodataLoader != "memconservative" {
		t.Fatalf("raw iOS geodata loader = %q, want memconservative", raw.GeodataLoader)
	}
	cfg := &config.Config{General: &config.General{GeodataLoader: "standard"}}
	overrideForAppleConfig(cfg, policy)
	if cfg.General.GeodataLoader != "memconservative" {
		t.Fatalf("parsed iOS geodata loader = %q, want memconservative", cfg.General.GeodataLoader)
	}
}

func TestMacOSPacketTunnelKeepsEveryOwnerMetadataRule(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-NAME-REGEX,^cur.*,REJECT
  - PROCESS-NAME-WILDCARD,cur*,REJECT
  - PROCESS-PATH,/usr/bin/curl,REJECT
  - PROCESS-PATH-REGEX,^/usr/bin/.*,REJECT
  - PROCESS-PATH-WILDCARD,/usr/bin/*,REJECT
  - UID,501,REJECT
  - IN-USER,alice,REJECT
  - SOURCE-APP-SIGNING-ID,com.example.cli,REJECT
  - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
  - MATCH,DIRECT
sub-rules:
  child:
    - PROCESS-NAME,ssh,REJECT
    - SOURCE-APP-SIGNING-ID,com.example.cli,REJECT
    - DOMAIN,child.example,DIRECT
rule-providers:
  inline:
    type: inline
    behavior: classical
    payload:
      - PROCESS-PATH,/usr/bin/ssh
      - SOURCE-APP-TEAM-ID,ABCDE12345
      - DOMAIN,provider.example
`))
	if err != nil {
		t.Fatal(err)
	}

	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileMacOSPacketTunnel, true))

	want := []string{
		"PROCESS-NAME,curl,REJECT",
		"PROCESS-NAME-REGEX,^cur.*,REJECT",
		"PROCESS-NAME-WILDCARD,cur*,REJECT",
		"PROCESS-PATH,/usr/bin/curl,REJECT",
		"PROCESS-PATH-REGEX,^/usr/bin/.*,REJECT",
		"PROCESS-PATH-WILDCARD,/usr/bin/*,REJECT",
		"UID,501,REJECT",
		"IN-USER,alice,REJECT",
		"SOURCE-APP-SIGNING-ID,com.example.cli,REJECT",
		"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(raw.Rule, want) {
		t.Fatalf("macOS Packet Tunnel rules = %v, want %v", raw.Rule, want)
	}
	if want := []string{"PROCESS-NAME,ssh,REJECT", "SOURCE-APP-SIGNING-ID,com.example.cli,REJECT", "DOMAIN,child.example,DIRECT"}; !reflect.DeepEqual(raw.SubRules["child"], want) {
		t.Fatalf("macOS Packet Tunnel sub-rules = %v, want %v", raw.SubRules["child"], want)
	}
	if want := []any{"PROCESS-PATH,/usr/bin/ssh", "SOURCE-APP-TEAM-ID,ABCDE12345", "DOMAIN,provider.example"}; !reflect.DeepEqual(raw.RuleProvider["inline"]["payload"], want) {
		t.Fatalf("macOS Packet Tunnel inline provider = %#v, want %#v", raw.RuleProvider["inline"]["payload"], want)
	}

	if raw.FindProcessMode == process.FindProcessOff {
		t.Fatal("find-process-mode was forced off, which makes every PROCESS rule kept above " +
			"match nothing -- the rules and the lookup have to be enabled together")
	}
}

func TestIOSPacketTunnelKeepsEveryMetadataRuleAndForcesLookupOff(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
rules:
  - PROCESS-NAME,curl,REJECT
  - PROCESS-PATH,/usr/bin/curl,REJECT
  - UID,501,REJECT
  - SOURCE-APP-TEAM-ID,ABCDE12345,REJECT
  - MATCH,DIRECT
`))
	if err != nil {
		t.Fatal(err)
	}

	normalizeRawConfigForApple(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))

	want := []string{
		"PROCESS-NAME,curl,REJECT",
		"PROCESS-PATH,/usr/bin/curl,REJECT",
		"SOURCE-APP-TEAM-ID,ABCDE12345,REJECT",
		"MATCH,DIRECT",
	}
	if !reflect.DeepEqual(raw.Rule, want) {
		t.Fatalf("iOS rules = %v, want %v", raw.Rule, want)
	}
	if raw.FindProcessMode != process.FindProcessOff {
		t.Fatalf("iOS find-process-mode = %v, want off: the default is Strict, which would "+
			"attempt a lookup on every connection that cannot succeed", raw.FindProcessMode)
	}
}
