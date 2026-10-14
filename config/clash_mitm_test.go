package config

import (
	"testing"
)

// TestParseMITMDocsExample loads the mitm block exactly as it appears in the
// example config (docs/config.yaml): the rewrite entry uses a value-prefix
// header rule with no value — the combination the example previously shipped
// (value AND value-prefix on one header) was rejected by Normalize, so the
// documented config could not load at all.
func TestParseMITMDocsExample(t *testing.T) {
	text := `mitm:
  enable: true
  store-dir: ""
  hosts:
    - +.example.com
    - api.example.org
  skip-domain:
    - auth.example.com
  https-ports: ["443"]
  rewrite:
    - url-pattern: "api.example.com/v1/"
      headers:
        - action: set
          name: User-Agent
          value: "ClashMITM/1.0"
        - action: set
          name: Authorization
          value-prefix: "Bearer "
`
	raw, err := UnmarshalRawConfig([]byte(text))
	if err != nil {
		t.Fatalf("UnmarshalRawConfig: %v", err)
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil {
		t.Fatalf("ParseRawConfig: %v", err)
	}
	if cfg.MITM == nil || !cfg.MITM.Enable {
		t.Fatal("mitm block did not parse as enabled")
	}
	if len(cfg.MITM.HostGates) != 2 || cfg.MITM.HostGates[0] != ".example.com" || cfg.MITM.HostGates[1] != "api.example.org" {
		t.Fatalf("HostGates = %v", cfg.MITM.HostGates)
	}
	if len(cfg.MITM.SkipDomains) != 1 || cfg.MITM.SkipDomains[0] != "auth.example.com" {
		t.Fatalf("SkipDomains = %v", cfg.MITM.SkipDomains)
	}
	if len(cfg.MITM.RewritePolicies) != 1 {
		t.Fatalf("RewritePolicies = %d", len(cfg.MITM.RewritePolicies))
	}
	rules := cfg.MITM.RewritePolicies[0].HeaderRules
	if len(rules) != 2 {
		t.Fatalf("HeaderRules = %d", len(rules))
	}
	if rules[1].ValuePrefix != "Bearer " || rules[1].Value != "" {
		t.Fatalf("prefix rule parsed as %+v", rules[1])
	}

	// The parsed config must actually match traffic end-to-end through
	// TrafficMatch (suffix gates, punycode-safe): api.example.com:443 hits
	// the policy, auth.example.com is skipped, api.example.org has no
	// policy and is therefore not intercepted.
	policy, ok := cfg.MITM.TrafficMatch("api.example.com", "https", 443, "/v1/x")
	if !ok || len(policy.HeaderRules) != 2 {
		t.Fatalf("TrafficMatch(api.example.com) = %+v, %v", policy, ok)
	}
	if cfg.MITM.MatchHost("auth.example.com") {
		t.Fatal("skip-domain must exclude auth.example.com")
	}
	if _, ok := cfg.MITM.TrafficMatch("api.example.org", "https", 443, "/v1/x"); ok {
		t.Fatal("gated host without a policy must not be intercepted")
	}
}

// TestParseMITMRejectsInvalidGuard rails: a value+value-prefix combination
// must fail at load with the punycode guidance where applicable.
func TestParseMITMRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"value and prefix": "mitm:\n  enable: true\n  hosts: [a.com]\n  rewrite:\n    - url-pattern: \"a.com/\"\n      headers:\n        - {action: set, name: X, value: v, value-prefix: p}\n",
		"idn gate":         "mitm:\n  enable: true\n  hosts: [\"bücher.example.com\"]\n",
	}
	for name, text := range cases {
		raw, err := UnmarshalRawConfig([]byte(text))
		if err != nil {
			t.Fatalf("%s: UnmarshalRawConfig: %v", name, err)
		}
		if _, err := ParseRawConfig(raw); err == nil {
			t.Errorf("%s: ParseRawConfig accepted invalid mitm config", name)
		}
	}
}
