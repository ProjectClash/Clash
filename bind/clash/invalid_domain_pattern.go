package clash

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ProjectClash/Clash/common/orderedmap"
	"github.com/ProjectClash/Clash/component/trie"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func explainInvalidDomainPatterns(raw *config.RawConfig, cause error) error {
	if cause == nil || raw == nil {
		return cause
	}
	if !errors.Is(cause, trie.ErrInvalidDomain) && !strings.Contains(cause.Error(), "invalid domain") {
		return cause
	}
	sites := invalidDomainPatternSites(raw)
	if len(sites) == 0 {
		return cause
	}
	return fmt.Errorf("%w -- invalid domain pattern at %s (mihomo %s rejects a bare \"+\", a \"+\" outside "+
		"the leading label, and \"*\" inside a label; fix or remove the entry)",
		cause, strings.Join(sites, ", "), C.Version)
}

type invalidDomainPatternFinding struct {
	Field  string
	Index  int
	Key    string
	IsKey  bool
	Entry  string
	Reason string
}

func invalidDomainPatternSites(raw *config.RawConfig) []string {
	findings := invalidDomainPatternFindings(raw)
	sites := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.IsKey {
			sites = append(sites, fmt.Sprintf("%s[%q]", f.Field, f.Entry))
		} else {
			sites = append(sites, fmt.Sprintf("%s[%d] %q", f.Field, f.Index, f.Entry))
		}
	}
	return sites
}

func invalidDomainPatternFindings(raw *config.RawConfig) []invalidDomainPatternFinding {
	var findings []invalidDomainPatternFinding
	list := func(field string, entries []string) {
		for index, entry := range entries {
			if _, err := trie.ValidAndSplitDomain(entry); err != nil {
				findings = append(findings, invalidDomainPatternFinding{
					Field: field, Index: index, Entry: entry, Reason: classifyInvalidDomainPattern(entry),
				})
			}
		}
	}
	list("sniffer.force-domain", raw.Sniffer.ForceDomain)
	list("sniffer.skip-domain", raw.Sniffer.SkipDomain)
	if len(raw.DNS.Fallback) != 0 {
		list("dns.fallback-filter.domain", raw.DNS.FallbackFilter.Domain)
	}
	if raw.DNS.EnhancedMode == C.DNSFakeIP && raw.DNS.FakeIPFilterMode != C.FilterRule {
		list("dns.fake-ip-filter", raw.DNS.FakeIPFilter)
	}
	policy := func(field string, keys *orderedmap.OrderedMap[string, any]) {
		if keys == nil {
			return
		}
		for pair := keys.Oldest(); pair != nil; pair = pair.Next() {
			key := pair.Key
			lower := strings.ToLower(key)
			if strings.HasPrefix(lower, "geosite:") || strings.HasPrefix(lower, "rule-set:") {
				continue
			}
			for _, member := range strings.Split(key, ",") {
				if _, err := trie.ValidAndSplitDomain(member); err != nil {
					findings = append(findings, invalidDomainPatternFinding{
						Field: field, Key: key, IsKey: true, Entry: member, Reason: classifyInvalidDomainPattern(member),
					})
				}
			}
		}
	}
	policy("dns.nameserver-policy", raw.DNS.NameServerPolicy)
	policy("dns.proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy)
	return findings
}

func classifyInvalidDomainPattern(pattern string) string {
	if pattern != "" && pattern[len(pattern)-1] == '.' {
		return "trailing-dot"
	}
	if pattern != "" {
		if r, _ := utf8.DecodeRuneInString(pattern); unicode.IsSpace(r) {
			return "whitespace"
		}
		if r, _ := utf8.DecodeLastRuneInString(pattern); unicode.IsSpace(r) {
			return "whitespace"
		}
	}
	parts := strings.Split(strings.ToLower(pattern), ".")
	if len(parts) == 1 {
		if parts[0] == "" {
			return "empty"
		}
	} else {
		for _, part := range parts[1:] {
			if part == "" {
				return "empty-segment"
			}
		}
	}
	for i, part := range parts {
		if strings.Contains(part, "+") {
			if part == "+" && len(parts) == 1 {
				return "bare-plus"
			}
			if part != "+" || i != 0 {
				return "plus-outside-leading-label"
			}
		}
		if strings.Contains(part, "*") && part != "*" {
			return "star-inside-label"
		}
	}
	return "other"
}

type invalidDomainPatternJSONFinding struct {
	Field  string `json:"field"`
	Index  *int   `json:"index,omitempty"`
	Key    string `json:"key,omitempty"`
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
}

func InvalidDomainPatternsJSON(configContent string, targetProfile string) (*StringBox, error) {
	out, err := recoverAppCall("InvalidDomainPatternsJSON", func() (*StringBox, error) { return invalidDomainPatternsJSONUnguarded(configContent, targetProfile) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func invalidDomainPatternsJSONUnguarded(configContent string, targetProfile string) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(configContent))
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: parse config: %w", err))
	}
	if runtimePolicyFor(profile, true).networkExtension {
		stripNEIncompatibleNameservers(raw)
	}
	findings := invalidDomainPatternFindings(raw)
	out := make([]invalidDomainPatternJSONFinding, 0, len(findings))
	for _, f := range findings {
		item := invalidDomainPatternJSONFinding{Field: f.Field, Entry: f.Entry, Reason: f.Reason}
		if f.IsKey {
			item.Key = f.Key
		} else {
			index := f.Index
			item.Index = &index
		}
		out = append(out, item)
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: encode invalid domain patterns: %w", err))
	}
	return WrapString(string(data)), nil
}
