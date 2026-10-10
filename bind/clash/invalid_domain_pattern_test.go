package clash

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/trie"
	"github.com/ProjectClash/Clash/config"
)

var errInvalidDomainProbe = errors.New("DNS ResoverRule invalid domain: somewhere-this-diagnostic-cannot-see")

func TestInvalidDomainPatternRejectionNamesTheFieldAndTheEntry(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "sniffer.force-domain bare plus",
			yaml: "sniffer:\n  enable: true\n  force-domain:\n    - example.com\n    - '+'\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `sniffer.force-domain[1] "+"`,
		},
		{
			name: "sniffer.skip-domain partial star",
			yaml: "sniffer:\n  enable: true\n  skip-domain:\n    - 'a*b.example.com'\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `sniffer.skip-domain[0] "a*b.example.com"`,
		},
		{
			name: "dns.nameserver-policy key",
			yaml: "dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  nameserver-policy:\n    'fine.example.com': 1.1.1.1\n    '+': 1.1.1.1\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `dns.nameserver-policy["+"]`,
		},
		{
			name: "dns.nameserver-policy comma list names only the bad member",
			yaml: "dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  nameserver-policy:\n    'ok.example.com,bad*.example.com': 1.1.1.1\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `dns.nameserver-policy["bad*.example.com"]`,
		},
		{
			name: "dns.proxy-server-nameserver-policy key",
			yaml: "dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  proxy-server-nameserver-policy:\n    'x.+.example.com': 1.1.1.1\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `dns.proxy-server-nameserver-policy["x.+.example.com"]`,
		},
		{
			name: "dns.fallback-filter.domain",
			yaml: "dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  fallback: [1.1.1.1]\n  fallback-filter:\n    geoip: false\n    domain: ['fine.example.com', 'a*b.example.com']\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `dns.fallback-filter.domain[1] "a*b.example.com"`,
		},
		{
			name: "dns.fake-ip-filter under fake-ip",
			yaml: "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [8.8.8.8]\n  fake-ip-filter:\n    - '*abc.example.com'\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
			want: `dns.fake-ip-filter[0] "*abc.example.com"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckConfig(tc.yaml)
			if err == nil {
				t.Fatalf("mihomo accepted a pattern this test believes it rejects; the case is wrong, not the core")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the rejection does not name the field and the entry:\n  got  %q\n  want it to contain %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "invalid domain") {
				t.Fatalf("upstream's own verdict is no longer in the message: %q", err.Error())
			}
		})
	}
}

func TestValidDomainPatternsAreNotReported(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	yaml := "sniffer:\n  enable: true\n  force-domain:\n    - '+.example.com'\n    - '*.example.com'\n    - '.example.com'\n    - 'sub.*.example.com'\n  skip-domain:\n    - 'www.example.com'\n" +
		"dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [8.8.8.8]\n  fake-ip-filter:\n    - '*.lan'\n    - '+.local'\n  nameserver-policy:\n    '+.example.org,*.example.net': 1.1.1.1\n" +
		"proxies: []\nrules:\n  - MATCH,DIRECT\n"
	if err := CheckConfig(yaml); err != nil {
		t.Fatalf("valid patterns were rejected: %v", err)
	}
}

func TestInvalidDomainDiagnosticNeverRejectsWhatMihomoAccepts(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	yaml := "dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [8.8.8.8]\n  fake-ip-filter:\n    - '*abc.example.com'\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	if err := CheckConfig(yaml); err != nil {
		t.Fatalf("mihomo accepts this configuration and Clash refused it: %v", err)
	}
}

func TestInvalidDomainDiagnosticFallsBackToTheOriginalError(t *testing.T) {
	err := explainInvalidDomainPatterns(nil, errInvalidDomainProbe)
	if err == nil || err.Error() != errInvalidDomainProbe.Error() {
		t.Fatalf("with nothing to explain the error must pass through verbatim, got %v", err)
	}
}

func TestInvalidDomainPatternWalkerSkipsGeositeAndRuleSetKeys(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte("dns:\n  nameserver-policy:\n    'geosite:cn': 1.1.1.1\n    'RULE-SET:private': 1.1.1.1\n    'geosite:+': 1.1.1.1\n    'ok.example.com,+': 1.1.1.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	sites := invalidDomainPatternSites(raw)
	if len(sites) != 1 || sites[0] != `dns.nameserver-policy["+"]` {
		t.Fatalf("want exactly the comma-list member \"+\" reported, got %v", sites)
	}
}

func TestInvalidDomainPatternWalkerReadsAFieldOnlyWhereMihomoDoes(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "fake-ip-filter under redir-host is not a domain field",
			yaml: "dns:\n  enhanced-mode: redir-host\n  fake-ip-filter: ['*abc.example.com']\nsniffer:\n  force-domain: ['+']\n",
			want: []string{`sniffer.force-domain[0] "+"`},
		},
		{
			name: "fake-ip-filter under fake-ip is",
			yaml: "dns:\n  enhanced-mode: fake-ip\n  fake-ip-filter: ['*abc.example.com']\n",
			want: []string{`dns.fake-ip-filter[0] "*abc.example.com"`},
		},
		{
			name: "fake-ip-filter-mode rule holds rules, not domains",
			yaml: "dns:\n  enhanced-mode: fake-ip\n  fake-ip-filter-mode: rule\n  fake-ip-filter: ['*abc.example.com']\n",
			want: nil,
		},
		{
			name: "fallback-filter.domain without a fallback server is never parsed",
			yaml: "dns:\n  fallback-filter:\n    domain: ['a*b.example.com']\n",
			want: nil,
		},
		{
			name: "fallback-filter.domain with a fallback server is",
			yaml: "dns:\n  fallback: [1.1.1.1]\n  fallback-filter:\n    domain: ['a*b.example.com']\n",
			want: []string{`dns.fallback-filter.domain[0] "a*b.example.com"`},
		},
		{
			name: "sniffer and policy keys are read whether or not the feature is enabled",
			yaml: "sniffer:\n  enable: false\n  skip-domain: ['a*b']\ndns:\n  enable: false\n  nameserver-policy:\n    '+': 1.1.1.1\n",
			want: []string{`sniffer.skip-domain[0] "a*b"`, `dns.nameserver-policy["+"]`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got := invalidDomainPatternSites(raw)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("sites = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInvalidDomainRejectionDoesNotPointAtEntriesMihomoNeverParsed(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	yaml := "dns:\n  enable: true\n  enhanced-mode: redir-host\n  nameserver: [8.8.8.8]\n  fake-ip-filter:\n    - '*abc.example.com'\n" +
		"sniffer:\n  enable: true\n  force-domain:\n    - '+'\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	err := CheckConfig(yaml)
	if err == nil {
		t.Fatal("mihomo accepted a bare \"+\" in sniffer.force-domain; the case is wrong, not the core")
	}
	if !strings.Contains(err.Error(), `sniffer.force-domain[0] "+"`) {
		t.Fatalf("the rejection does not name the sniffer entry: %q", err.Error())
	}
	if strings.Contains(err.Error(), "fake-ip-filter") {
		t.Fatalf("the rejection points at dns.fake-ip-filter, which mihomo does not parse under redir-host: %q", err.Error())
	}
}

func TestInvalidDomainPatternReasonsFollowUpstreamsVerdict(t *testing.T) {
	cases := []struct {
		pattern string
		reason  string
	}{
		{"+", "bare-plus"},
		{"x.+", "plus-outside-leading-label"},
		{"x.+.y", "plus-outside-leading-label"},
		{"+abc", "plus-outside-leading-label"},
		{"abc+.x", "plus-outside-leading-label"},
		{"+.a+b", "plus-outside-leading-label"},
		{"*abc", "star-inside-label"},
		{"abc*", "star-inside-label"},
		{"a*b", "star-inside-label"},
		{"*.a*b", "star-inside-label"},
		{"+.a*b", "star-inside-label"},
		{"a.com.", "trailing-dot"},
		{" example.com", "whitespace"},
		{"example.com ", "whitespace"},
		{"a..b", "empty-segment"},
		{"a.", "trailing-dot"},
		{"..", "trailing-dot"},
		{"", "empty"},
		{"*.example.com", ""},
		{"sub.*.example.com", ""},
		{"*", ""},
		{"+.example.com", ""},
		{".example.com", ""},
		{"example.com", ""},
		{"EXAMPLE.com", ""},
	}
	for _, tc := range cases {
		_, err := trie.ValidAndSplitDomain(tc.pattern)
		valid := err == nil
		got := classifyInvalidDomainPattern(tc.pattern)
		if valid && tc.reason != "" {
			t.Errorf("%q: this test expects a refusal (%s) but upstream accepts it; fix the table, not the core", tc.pattern, tc.reason)
			continue
		}
		if !valid && tc.reason == "" {
			t.Errorf("%q: upstream refuses it and this test expected acceptance; a new tightening -- classify it", tc.pattern)
			continue
		}
		if !valid && got != tc.reason {
			t.Errorf("%q: reason = %q, want %q", tc.pattern, got, tc.reason)
		}
	}
}

func TestInvalidDomainPatternsJSONLocatesEveryRefusedEntry(t *testing.T) {
	yaml := "sniffer:\n  enable: false\n  force-domain:\n    - example.com\n    - '+'\n  skip-domain:\n    - 'a*b.example.com'\n" +
		"dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [8.8.8.8]\n  fallback: [1.1.1.1]\n" +
		"  fake-ip-filter:\n    - '*.lan'\n    - '*abc.example.com'\n" +
		"  fallback-filter:\n    geoip: false\n    domain: ['fine.example.com', 'x.+.example.com']\n" +
		"  nameserver-policy:\n    'ok.example.com,bad*.example.com': 1.1.1.1\n    '+': 1.1.1.1\n    'rule-set:not-a-pattern+': 1.1.1.1\n" +
		"  proxy-server-nameserver-policy:\n    'example.com.': 1.1.1.1\n" +
		"proxies: []\nrules:\n  - MATCH,DIRECT\n"
	box, err := InvalidDomainPatternsJSON(yaml, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(box.Value), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, box.Value)
	}
	want := []map[string]any{
		{"field": "sniffer.force-domain", "index": 1.0, "entry": "+", "reason": "bare-plus"},
		{"field": "sniffer.skip-domain", "index": 0.0, "entry": "a*b.example.com", "reason": "star-inside-label"},
		{"field": "dns.fallback-filter.domain", "index": 1.0, "entry": "x.+.example.com", "reason": "plus-outside-leading-label"},
		{"field": "dns.fake-ip-filter", "index": 1.0, "entry": "*abc.example.com", "reason": "star-inside-label"},
		{"field": "dns.nameserver-policy", "key": "ok.example.com,bad*.example.com", "entry": "bad*.example.com", "reason": "star-inside-label"},
		{"field": "dns.nameserver-policy", "key": "+", "entry": "+", "reason": "bare-plus"},
		{"field": "dns.proxy-server-nameserver-policy", "key": "example.com.", "entry": "example.com.", "reason": "trailing-dot"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d:\n%s", len(got), len(want), box.Value)
	}
	for i := range want {
		for k, v := range want[i] {
			if got[i][k] != v {
				t.Errorf("finding %d %s = %v, want %v (%v)", i, k, got[i][k], v, got[i])
			}
		}
		_, hasIndex := got[i]["index"]
		_, hasKey := got[i]["key"]
		if hasIndex == hasKey {
			t.Errorf("finding %d must carry exactly one of index/key: %v", i, got[i])
		}
		if _, ok := got[i]["entry"]; !ok {
			t.Errorf("finding %d has no entry: %v", i, got[i])
		}
	}
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	if err := CheckConfig(yaml); err == nil || !strings.Contains(err.Error(), `sniffer.force-domain[1] "+"`) {
		t.Fatalf("CheckConfig should refuse this configuration naming the same site, got %v", err)
	}
}

func TestInvalidDomainPatternsJSONIsEmptyForACleanConfigurationAndErrsOnlyOnDecode(t *testing.T) {
	clean := "sniffer:\n  enable: true\n  force-domain: ['+.example.com', '*.example.com', '.example.com']\n" +
		"dns:\n  enable: true\n  enhanced-mode: fake-ip\n  nameserver: [8.8.8.8]\n  fake-ip-filter: ['*.lan']\n  nameserver-policy:\n    '+.example.org,*.example.net': 1.1.1.1\n    'geosite:+': 1.1.1.1\n" +
		"proxies: []\nrules:\n  - MATCH,DIRECT\n"
	box, err := InvalidDomainPatternsJSON(clean, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	if box.Value != "[]" {
		t.Fatalf("a clean configuration must yield [] (not null, not omitted), got %q", box.Value)
	}
	box, err = InvalidDomainPatternsJSON("dns:\n  enhanced-mode: redir-host\n  fake-ip-filter: ['+']\n", "")
	if err != nil || box.Value != "[]" {
		t.Fatalf("redir-host fake-ip-filter must not be reported: %q %v", box.Value, err)
	}
	if _, err := InvalidDomainPatternsJSON("dns: [not a map\n", ""); err == nil {
		t.Fatal("undecodable YAML must return an error, not an empty list")
	}
	if _, err := InvalidDomainPatternsJSON("dns: {}\n", "someOtherProfile"); err == nil {
		t.Fatal("an unknown target profile must be an error")
	}
	if box, err := InvalidDomainPatternsJSON("", ""); err != nil || box.Value != "[]" {
		t.Fatalf("an empty document is a clean one: %q %v", box, err)
	}
}

func TestInvalidDomainPatternsJSONFollowsTheTargetProfilesStrip(t *testing.T) {
	yaml := "dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  fallback: [system]\n  fallback-filter:\n    domain: ['a*b.example.com']\nproxies: []\nrules:\n  - MATCH,DIRECT\n"
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileMacOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		box, err := InvalidDomainPatternsJSON(yaml, profile)
		if err != nil || box.Value != "[]" {
			t.Fatalf("%s: fallback is stripped to nothing under a packet tunnel, so fallback-filter.domain is never parsed: got %q %v", profile, box.Value, err)
		}
	}
	box, err := InvalidDomainPatternsJSON(yaml, RuntimeProfileMacOSApplication)
	if err != nil || !strings.Contains(box.Value, `"dns.fallback-filter.domain"`) {
		t.Fatalf("macosApplication keeps dns.fallback as written, so the entry is parsed and must be reported: got %q %v", box.Value, err)
	}
	again, err := InvalidDomainPatternsJSON(yaml, RuntimeProfileMacOSApplication)
	if err != nil || again.Value != box.Value {
		t.Fatalf("the walk is not idempotent: %q then %q", box.Value, again.Value)
	}
}
