package clash

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/age"
	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"github.com/klauspost/compress/zstd"
	"go.yaml.in/yaml/v3"
)

type recordingProviderCloser struct {
	closeCount int
	closeErr   error
}

func (c *recordingProviderCloser) Close() error {
	c.closeCount++
	return c.closeErr
}

func TestParseAndCloseProviderOutbound(t *testing.T) {
	mapping := map[string]any{"name": "fixture", "type": "direct"}
	t.Run("success closes exactly once", func(t *testing.T) {
		closer := &recordingProviderCloser{}
		err := parseAndCloseProviderOutbound(mapping, func(map[string]any) (io.Closer, error) {
			return closer, nil
		})
		if err != nil || closer.closeCount != 1 {
			t.Fatalf("validate close = %v, count = %d", err, closer.closeCount)
		}
	})
	t.Run("parse error has no object to close", func(t *testing.T) {
		closer := &recordingProviderCloser{}
		parseErr := errors.New("parse failed")
		err := parseAndCloseProviderOutbound(mapping, func(map[string]any) (io.Closer, error) {
			return closer, parseErr
		})
		if !errors.Is(err, parseErr) || closer.closeCount != 0 {
			t.Fatalf("parse error = %v, close count = %d", err, closer.closeCount)
		}
	})
	t.Run("close error rejects candidate", func(t *testing.T) {
		closeErr := errors.New("close failed")
		closer := &recordingProviderCloser{closeErr: closeErr}
		err := parseAndCloseProviderOutbound(mapping, func(map[string]any) (io.Closer, error) {
			return closer, nil
		})
		if !errors.Is(err, closeErr) || closer.closeCount != 1 {
			t.Fatalf("close error = %v, count = %d", err, closer.closeCount)
		}
	})
}

func TestDecryptAgeForIOSUsesExplicitKey(t *testing.T) {
	secret, public, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("payload:\n  - DOMAIN,example.com\n")
	encrypted, err := age.EncryptBytes(plaintext, public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAgeForIOS(encrypted, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
	if _, err := DecryptAgeForIOS(encrypted, "not-a-key"); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestValidateProviderForIOSAcceptsMRS(t *testing.T) {
	for _, test := range []struct {
		behaviorName string
		behavior     P.RuleBehavior
		text         string
	}{
		{behaviorName: "domain", behavior: P.Domain, text: "example.com\n"},
		{behaviorName: "ipcidr", behavior: P.IPCIDR, text: "10.0.0.0/8\n2001:db8::/32\n"},
	} {
		t.Run(test.behaviorName, func(t *testing.T) {
			var encoded bytes.Buffer
			if err := ruleprovider.ConvertToMrs(
				[]byte(test.text),
				test.behavior,
				P.TextRule,
				&encoded,
			); err != nil {
				t.Fatal(err)
			}
			if err := ValidateProviderForIOS("rule", test.behaviorName, "mrs", encoded.Bytes()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProviderEntryCountForIOS(t *testing.T) {
	tests := []struct {
		name     string
		kind     string
		behavior string
		format   string
		payload  []byte
		want     int
	}{
		{
			name: "proxy yaml", kind: "proxy", format: "yaml", want: 2,
			payload: []byte("proxies:\n  - {name: One, type: direct}\n  - {name: Two, type: direct}\n"),
		},
		{
			name: "domain yaml", kind: "rule", behavior: "domain", format: "yaml", want: 2,
			payload: []byte("payload:\n  - example.com\n  - example.net\n"),
		},
		{
			name: "ipcidr text", kind: "rule", behavior: "ipcidr", format: "text", want: 2,
			payload: []byte("# ignored\n192.0.2.0/24\n198.51.100.0/24\n"),
		},
		{
			name: "classical yaml", kind: "rule", behavior: "classical", format: "yaml", want: 2,
			payload: []byte("payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.net\n"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ProviderEntryCountForIOS(
				test.kind, test.behavior, test.format, test.payload,
			)
			if err != nil {
				t.Fatalf("ProviderEntryCountForIOS: %v", err)
			}
			if got != test.want {
				t.Fatalf("count = %d, want %d", got, test.want)
			}
		})
	}
}

func TestProviderEntryCountForIOSRoundTripsAKernelWrittenMRS(t *testing.T) {
	var encoded bytes.Buffer
	if err := ruleprovider.ConvertToMrs(
		[]byte("example.com\nexample.net\n"),
		P.Domain,
		P.TextRule,
		&encoded,
	); err != nil {
		t.Fatalf("build mrs: %v", err)
	}
	got, err := ProviderEntryCountForIOS("rule", "domain", "mrs", encoded.Bytes())
	if err != nil {
		t.Fatalf("ProviderEntryCountForIOS: %v", err)
	}
	if got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}

func TestProviderEntryCountForIOSRejectsUnparseablePayload(t *testing.T) {
	if _, err := ProviderEntryCountForIOS(
		"rule", "domain", "yaml", []byte("payload:"),
	); err == nil {
		t.Fatal("a body with no payload head was accepted; upstream returns ErrNoPayload")
	}
	count, err := ProviderEntryCountForIOS(
		"rule", "domain", "yaml", []byte("payload: []\n"),
	)
	if err != nil {
		t.Fatalf("an empty list was rejected; upstream reads it as zero rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("empty list counted %d, want 0", count)
	}
}

func TestValidateProviderForIOSRejectsUnsafeMRSLengthsWithoutPanicking(t *testing.T) {
	tests := map[string][]byte{
		"oversized extra": buildDecodedMRSTestPayload(t, P.Domain, 1, func(output *bytes.Buffer) {
			if err := binary.Write(output, binary.BigEndian, int64(^uint64(0)>>1)); err != nil {
				t.Fatal(err)
			}
		}),
		"oversized domain leaves length": buildDecodedMRSTestPayload(t, P.Domain, 1, func(output *bytes.Buffer) {
			if err := binary.Write(output, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			output.WriteByte(1)
			if err := binary.Write(output, binary.BigEndian, int64(^uint64(0)>>1)); err != nil {
				t.Fatal(err)
			}
		}),
	}
	for name, decoded := range tests {
		t.Run(name, func(t *testing.T) {
			payload := compressMRSTestPayload(t, decoded)
			var panicValue any
			var err error
			func() {
				defer func() { panicValue = recover() }()
				err = ValidateProviderForIOS("rule", "domain", "mrs", payload)
			}()
			if panicValue != nil {
				t.Fatalf("unsafe MRS panicked: %v", panicValue)
			}
			if err == nil {
				t.Fatal("unsafe MRS was accepted")
			}
		})
	}
}

func TestValidateProviderForIOSBoundsMRSDecompression(t *testing.T) {
	asTunnelProcess(t)
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 1, func(output *bytes.Buffer) {
		if err := binary.Write(output, binary.BigEndian, int64(maximumProviderResourceBytes)); err != nil {
			t.Fatal(err)
		}
		output.Write(bytes.Repeat([]byte{0}, maximumProviderResourceBytes))
	})
	payload := compressMRSTestPayload(t, decoded)
	if len(payload) >= maximumProviderResourceBytes {
		t.Fatalf("compressed fixture unexpectedly exceeds input cap: %d", len(payload))
	}
	err := ValidateProviderForIOS("rule", "domain", "mrs", payload)
	if err == nil || !strings.Contains(err.Error(), "decoded MRS payload exceeds") {
		t.Fatalf("MRS decompression limit error = %v", err)
	}
}

func buildDecodedMRSTestPayload(t *testing.T, behavior P.RuleBehavior, count int64, appendBody func(*bytes.Buffer)) []byte {
	t.Helper()
	var decoded bytes.Buffer
	decoded.Write(ruleprovider.MrsMagicBytes[:])
	decoded.WriteByte(behavior.Byte())
	if err := binary.Write(&decoded, binary.BigEndian, count); err != nil {
		t.Fatal(err)
	}
	appendBody(&decoded)
	return decoded.Bytes()
}

func compressMRSTestPayload(t *testing.T, decoded []byte) []byte {
	t.Helper()
	var payload bytes.Buffer
	encoder, err := zstd.NewWriter(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(decoded); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return payload.Bytes()
}

func TestValidateProviderForIOS(t *testing.T) {
	for _, test := range []struct {
		name, kind, behavior, format string
		payload                      []byte
		wantError                    bool
	}{
		{name: "rule yaml", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - DOMAIN,example.com\n")},
		{name: "rule text", kind: "rule", behavior: "domain", format: "text", payload: []byte("example.com\n")},
		{name: "proxy yaml", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n")},
		{name: "proxy share links", kind: "proxy", format: "yaml", payload: []byte("hysteria2://password@example.com:443/?sni=example.com#one\n")},
		{name: "proxy wrong root field", kind: "proxy", format: "yaml", payload: []byte("payload:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n"), wantError: true},
		{name: "proxy interface override tolerated", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    interface-name: en0\n")},
		{name: "proxy routing mark tolerated", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    routing-mark: 233\n")},
		{name: "paired proxy egress overrides tolerated", kind: "proxy", format: "yaml", payload: []byte("proxies:\n  - name: one\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    interface-name: en0\n    routing-mark: 233\n")},
		{name: "domain payload named like metadata", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - DOMAIN,process-name\n")},
		{name: "empty", kind: "rule", behavior: "classical", format: "yaml", payload: nil, wantError: true},
		{name: "malformed payload container", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  key: value\n"), wantError: true},
		{name: "process wildcard rule", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - PROCESS-NAME-WILDCARD,curl*\n")},
		{name: "uid rule", kind: "rule", behavior: "classical", format: "text", payload: []byte("UID,501\n")},
		{name: "in-user rule", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - IN-USER,alice\n")},
		{name: "logic nested metadata rule", kind: "rule", behavior: "classical", format: "yaml", payload: []byte("payload:\n  - AND,((PROCESS-PATH-REGEX,^/bin/.*),(NETWORK,TCP))\n")},
		{name: "bad proxy", kind: "proxy", format: "yaml", payload: []byte("payload:\n  - server: x\n"), wantError: true},
		{name: "proxy mrs", kind: "proxy", format: "mrs", payload: []byte("not mrs"), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateProviderForIOS(test.kind, test.behavior, test.format, test.payload)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestProviderEntryCountForIOSExcludesMetadataNoOps(t *testing.T) {
	payload := []byte(`
payload:
  - PROCESS-NAME,curl
  - DOMAIN,first.example
  - UID,501
  - IN-USER,alice
  - DOMAIN,second.example
`)
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("executable provider entry count = %d, want 2", count)
	}
}

func TestClassicalProviderSkipsUnsupportedEntryInsteadOfFailingWholeSet(t *testing.T) {
	payload := []byte(`
payload:
  - DOMAIN,keep.example
  - RULE-SET,unsupported-nested-set
  - DOMAIN-SUFFIX,also.example
`)
	if err := ValidateProviderForIOS("rule", "classical", "yaml", payload); err != nil {
		t.Fatalf("classical provider with one unsupported entry must load, got: %v", err)
	}
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("kept executable entry count = %d, want 2 (unsupported entry skipped)", count)
	}
}

func TestClassicalProviderLoadsEmptyWhenEveryEntryIsSkipped(t *testing.T) {
	payload := []byte(`
payload:
  - RULE-SET,one
  - SUB-RULE,(two)
`)
	if err := ValidateProviderForIOS("rule", "classical", "yaml", payload); err != nil {
		t.Fatalf("all-unsupported classical provider must load empty, got: %v", err)
	}
	count, err := ProviderEntryCountForIOS("rule", "classical", "yaml", payload)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("kept executable entry count = %d, want 0", count)
	}
}

func TestEmptyClassicalProviderIsZeroRulesNotAnError(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte("payload:\n"),
		[]byte("payload:\n  # nothing in this list yet\n"),
	} {
		if err := validateClassicalProvider(payload, P.YamlRule); err != nil {
			t.Errorf("rejected %q, which upstream reads as zero rules: %v",
				string(payload), err)
		}
	}
	if err := validateClassicalProvider([]byte("# nothing yet\n"), P.TextRule); err != nil {
		t.Errorf("rejected a comment-only text provider, which upstream reads as "+
			"zero rules: %v", err)
	}
}

func TestClassicalProviderReadsBothPayloadAndRulesKeys(t *testing.T) {
	body := []byte("rules:\n  - PROCESS-NAME,evil,DIRECT\n  - DOMAIN-SUFFIX,example.com,DIRECT\n")

	sanitized, count, stripped, err := sanitizeClassicalProviderPayloadForIOS(body, P.YamlRule)
	if err != nil {
		t.Fatalf("rules-keyed provider rejected: %v", err)
	}
	if count == 0 {
		t.Fatalf("counted 0 entries for a provider with 2 rules; the `rules:` key was ignored")
	}
	if len(stripped) == 0 {
		t.Errorf("PROCESS-NAME survived the Apple metadata strip in a rules-keyed provider")
	}
	if string(sanitized) == string(body) {
		t.Errorf("payload was handed back untouched, so nothing was sanitized")
	}
}

func TestClassicalProviderWithoutPayloadHeadIsStillRejected(t *testing.T) {
	if err := validateClassicalProvider([]byte("payload:"), P.YamlRule); err == nil {
		t.Error("accepted a YAML payload with no head line; upstream returns ErrNoPayload")
	}
	if err := validateClassicalProvider([]byte("# nothing"), P.YamlRule); err == nil {
		t.Error("accepted a comment-only YAML body with no head line; upstream returns ErrNoPayload")
	}
	for _, ok := range [][]byte{[]byte("payload:\n"), []byte("rules:\n")} {
		if err := validateClassicalProvider(ok, P.YamlRule); err != nil {
			t.Errorf("rejected %q, which upstream parses to zero rules: %v", string(ok), err)
		}
	}
}

func TestEmptyDomainAndIPCIDRProvidersAreZeroRulesToo(t *testing.T) {
	for _, c := range []struct{ behavior, format, body string }{
		{"domain", "yaml", "payload:\n"},
		{"domain", "yaml", "payload: []\n"},
		{"domain", "text", "# nothing in this list yet\n"},
		{"ipcidr", "yaml", "payload:\n"},
	} {
		if err := ValidateProviderForIOS("rule", c.behavior, c.format, []byte(c.body)); err != nil {
			t.Errorf("%s/%s %q rejected; upstream loads it as zero rules: %v",
				c.behavior, c.format, c.body, err)
		}
		count, err := ProviderEntryCountForIOS("rule", c.behavior, c.format, []byte(c.body))
		if err != nil {
			t.Errorf("%s/%s %q count failed: %v", c.behavior, c.format, c.body, err)
		} else if count != 0 {
			t.Errorf("%s/%s %q counted %d, want 0", c.behavior, c.format, c.body, count)
		}
	}
}

func TestUpstreamEmptyRuleErrorTextIsUnchanged(t *testing.T) {
	err := ruleprovider.ConvertToMrs([]byte("payload:\n"), P.Domain, P.YamlRule, io.Discard)
	if err == nil {
		t.Fatal("ConvertToMrs accepted an empty rule set; the guard below is now dead code")
	}
	if err.Error() != upstreamEmptyRuleMessage {
		t.Fatalf("ConvertToMrs empty-set error = %q, want %q; update "+
			"isUpstreamEmptyRuleError and re-check the empty-provider paths",
			err.Error(), upstreamEmptyRuleMessage)
	}
}

func TestInspectProviderMatchesValidateThenCount(t *testing.T) {
	classical := []byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,www.example.org\n")
	unreadable := []byte("payload: not-a-list\n")
	notMRS := []byte("this is not a compiled rule set at all")

	for name, testCase := range map[string]struct {
		kind, behavior, format string
		payload                []byte
	}{
		"classical accepted":  {"rule", "classical", "yaml", classical},
		"classical unusable":  {"rule", "classical", "yaml", unreadable},
		"mrs that is not mrs": {"rule", "domain", "mrs", notMRS},
		"unknown kind":        {"widget", "domain", "yaml", classical},
		"empty payload":       {"rule", "domain", "yaml", nil},
	} {
		t.Run(name, func(t *testing.T) {
			validateErr := ValidateProviderForIOS(
				testCase.kind, testCase.behavior, testCase.format, testCase.payload)
			wantCount, countErr := ProviderEntryCountForIOS(
				testCase.kind, testCase.behavior, testCase.format, testCase.payload)
			gotCount, gotErr := InspectProviderForIOS(
				testCase.kind, testCase.behavior, testCase.format, testCase.payload)

			if (validateErr == nil) != (gotErr == nil) {
				t.Fatalf("validate said %v, one-pass said %v", validateErr, gotErr)
			}
			if validateErr != nil {
				if gotErr.Error() != validateErr.Error() {
					t.Fatalf("one-pass reported %q, validate reported %q",
						gotErr.Error(), validateErr.Error())
				}
				return
			}
			if countErr != nil {
				t.Fatalf("count failed where validate passed: %v", countErr)
			}
			if gotCount != wantCount {
				t.Fatalf("count = %d, want %d", gotCount, wantCount)
			}
		})
	}
}

func TestConvertProxiesForIOSTurnsAShareLinkIntoAProxyDocument(t *testing.T) {
	link := []byte("hysteria2://password@example.com:443/?sni=example.com#one\n")
	box, err := ConvertProxiesForIOS(link)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(box.Value), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(doc.Proxies))
	}
	if got := doc.Proxies[0]["name"]; got != "one" {
		t.Fatalf("name = %v, want one", got)
	}
	if got := doc.Proxies[0]["server"]; got != "example.com" {
		t.Fatalf("server = %v, want example.com", got)
	}
}

func TestConvertProxiesForIOSReparsesShadowrocketLegacyVlessAuthority(t *testing.T) {
	link := []byte("vless://bm9uZToxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTFAZWRnZS5leGFtcGxlLmludmFsaWQ6NDQz?type=tcp#legacy")
	box, err := ConvertProxiesForIOS(link)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(box.Value), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(doc.Proxies))
	}
	proxy := doc.Proxies[0]
	if got := proxy["uuid"]; got != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("uuid = %v", got)
	}
	if got := proxy["server"]; got != "edge.example.invalid" {
		t.Fatalf("server = %v", got)
	}
	if got := proxy["port"]; got != "443" {
		t.Fatalf("port = %v", got)
	}
	if got := proxy["encryption"]; got != "none" {
		t.Fatalf("encryption = %v", got)
	}
}

func TestConvertProxiesForIOSRefusesTextThatIsNotProxies(t *testing.T) {
	if _, err := ConvertProxiesForIOS([]byte("not a share link")); err == nil {
		t.Fatal("want an error for unconvertible text")
	}
}

func TestConvertProxiesForIOSRefusesAnEmptyPayload(t *testing.T) {
	if _, err := ConvertProxiesForIOS(nil); err == nil {
		t.Fatal("want an error for an empty payload")
	}
}
