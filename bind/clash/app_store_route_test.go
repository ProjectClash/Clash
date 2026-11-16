package clash

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	mhttp "github.com/metacubex/http"
)

const appStoreFixtureProfiles = `[
  {
    "id": "p-late",
    "label": "Zeta",
    "order": 2,
    "activeRevision": "r2",
    "override": {"appendRules": ["DOMAIN,q,DIRECT"], "prependRules": false, "patchJSON": "", "unknownOverride": true},
    "legacyRuntimePatchJSON": "{\"tun\":{\"enable\":true}}",
    "source": {"kind": "url"},
    "unknownTop": "keep"
  },
  {
    "id": "p-active",
    "label": "XSUS",
    "order": -1,
    "activeRevision": "r1",
    "override": {"appendRules": ["DOMAIN,a,DIRECT"], "prependRules": true, "patchJSON": "{\"dns\":{}}", "unknownOverride": 7},
    "legacyRuntimePatchJSON": "{\"dns\":{\"nameserver-policy\":{\"+.didichuxing.com\":[\"10.78.226.116\"]},\"fake-ip-filter\":[\"+.example.com\"],\"enhanced-mode\":\"fake-ip\"},\"tun\":{\"enable\":true}}",
    "source": {},
    "unknownTop": {"nested": [1, 2]}
  }
]`

const appStoreFixtureActive = `{"profileID":"p-active","revision":"r1","schemaVersion":1}`

func appStoreFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	store := filepath.Join(home, appStoreDirectoryName)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, appStoreProfilesFile), []byte(appStoreFixtureProfiles), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, appStoreActiveFile), []byte(appStoreFixtureActive), 0o600); err != nil {
		t.Fatal(err)
	}
	return store
}

// appStoreCompact normalizes formatting so assertions survive re-indentation.
func appStoreCompact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, raw); err != nil {
		t.Fatalf("compact %s: %v", raw, err)
	}
	return buffer.String()
}

func appStoreRawEntries(t *testing.T, store string) []map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store, appStoreProfilesFile))
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("profiles.json is not readable after the write: %v", err)
	}
	return entries
}

func appStoreEntryOf(t *testing.T, entries []map[string]json.RawMessage, id string) map[string]json.RawMessage {
	t.Helper()
	index := appStoreEntryIndex(entries, id)
	if index < 0 {
		t.Fatalf("profile %q vanished", id)
	}
	return entries[index]
}

func TestAppStoreIndexReadsTheAppStore(t *testing.T) {
	store := appStoreFixture(t)
	index, err := loadAppStoreIndexAt(store)
	if err != nil {
		t.Fatalf("loadAppStoreIndexAt: %v", err)
	}
	if index.Active.ProfileID != "p-active" || index.Active.Revision != "r1" {
		t.Fatalf("active = %+v", index.Active)
	}
	if len(index.Profiles) != 2 {
		t.Fatalf("profiles = %+v", index.Profiles)
	}
	first, second := index.Profiles[0], index.Profiles[1]
	if first.ID != "p-active" || !first.Active || first.AppendedRules != 1 || !first.PrependedRules || !first.Patched {
		t.Fatalf("active profile summary = %+v", first)
	}
	if second.ID != "p-late" || second.Active || second.AppendedRules != 1 || second.PrependedRules || second.Patched {
		t.Fatalf("second profile summary = %+v", second)
	}
}

func TestAppStoreRulesUpdateKeepsUnknownFields(t *testing.T) {
	store := appStoreFixture(t)
	prepend := false
	appendRules := []string{"DOMAIN-SUFFIX,x,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT"}
	if err := saveAppStoreRulesAt(store, "p-active", appStoreRulesUpdate{PrependRules: &prepend, AppendRules: &appendRules}); err != nil {
		t.Fatalf("saveAppStoreRulesAt: %v", err)
	}
	rules, err := loadAppStoreRulesAt(store, "p-active")
	if err != nil {
		t.Fatalf("loadAppStoreRulesAt: %v", err)
	}
	if rules.PrependRules || len(rules.AppendRules) != 2 || rules.AppendRules[0] != appendRules[0] || rules.PatchJSON != `{"dns":{}}` {
		t.Fatalf("rules = %+v", rules)
	}

	entries := appStoreRawEntries(t, store)
	entry := appStoreEntryOf(t, entries, "p-active")
	if appStoreCompact(t, entry["unknownTop"]) != `{"nested":[1,2]}` {
		t.Errorf("unknown top-level field = %s", entry["unknownTop"])
	}
	override := appStoreOverride(entry)
	if appStoreCompact(t, override["unknownOverride"]) != "7" {
		t.Errorf("unknown override field = %s", override["unknownOverride"])
	}
	if string(override["patchJSON"]) != `"{\"dns\":{}}"` {
		t.Errorf("patchJSON = %s", override["patchJSON"])
	}
	if string(entry["legacyRuntimePatchJSON"]) == "" || string(entry["legacyRuntimePatchJSON"]) == "null" {
		t.Errorf("legacyRuntimePatchJSON = %s", entry["legacyRuntimePatchJSON"])
	}
	other := appStoreEntryOf(t, entries, "p-late")
	if appStoreCompact(t, other["unknownTop"]) != `"keep"` || appStoreCompact(t, appStoreOverride(other)["unknownOverride"]) != "true" {
		t.Errorf("the untouched profile changed: %v", other)
	}

	left, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range left {
		if strings.HasPrefix(entry.Name(), ".app-store-") {
			t.Errorf("a staging file was left behind: %s", entry.Name())
		}
	}
	if _, err := loadAppStoreIndexAt(store); err != nil {
		t.Errorf("the rewritten index no longer loads: %v", err)
	}
}

func TestAppStoreRulesUpdateRejectsInvalidRules(t *testing.T) {
	for name, rules := range map[string][]string{
		"empty rule": {""},
		"line break": {"DOMAIN,a,\nDIRECT"},
		"carriage":   {"DOMAIN,a,\rDIRECT"},
		"nul":        {"DOMAIN,a,\x00DIRECT"},
		"oversized":  {strings.Repeat("a", appStoreMaximumRuleBytes+1)},
		"too many":   make([]string, appStoreMaximumAppendRules+1),
	} {
		if err := validateAppStoreRules(rules); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	if err := validateAppStoreRules([]string{"DOMAIN-SUFFIX,x,DIRECT"}); err != nil {
		t.Errorf("a valid rule was rejected: %v", err)
	}

	store := appStoreFixture(t)
	before, err := os.ReadFile(filepath.Join(store, appStoreProfilesFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := saveAppStoreRulesAt(store, "no-such-profile", appStoreRulesUpdate{AppendRules: &[]string{}}); !errors.Is(err, errAppStoreProfileMissing) {
		t.Errorf("unknown id error = %v", err)
	}
	after, err := os.ReadFile(filepath.Join(store, appStoreProfilesFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused write changed profiles.json")
	}
}

func TestAppStoreDNSPolicyKeepsOtherPatchKeys(t *testing.T) {
	store := appStoreFixture(t)
	policy := map[string][]string{"+.didichuxing.com": {"10.78.226.116", "https://dns.example/dns-query"}}
	if err := saveAppStoreDNSPolicyAt(store, "p-active", appStoreDNSPolicyUpdate{NameserverPolicy: &policy}); err != nil {
		t.Fatalf("saveAppStoreDNSPolicyAt: %v", err)
	}
	read, err := loadAppStoreDNSPolicyAt(store, "p-active")
	if err != nil {
		t.Fatalf("loadAppStoreDNSPolicyAt: %v", err)
	}
	if len(read.NameserverPolicy["+.didichuxing.com"]) != 2 || len(read.FakeIPFilter) != 1 || read.FakeIPFilter[0] != "+.example.com" {
		t.Fatalf("policy = %+v", read)
	}

	entries := appStoreRawEntries(t, store)
	entry := appStoreEntryOf(t, entries, "p-active")
	patch, err := appStorePatchObject(entry)
	if err != nil {
		t.Fatalf("the rewritten patch no longer parses: %v", err)
	}
	if string(patch["tun"]) != `{"enable":true}` {
		t.Errorf("the tun key was dropped: %s", patch["tun"])
	}
	dns := appStoreNestedObject(patch, "dns")
	if string(dns["enhanced-mode"]) != `"fake-ip"` {
		t.Errorf("the enhanced-mode key was dropped: %s", dns["enhanced-mode"])
	}

	if err := saveAppStoreDNSPolicyAt(store, "p-active", appStoreDNSPolicyUpdate{NameserverPolicy: &map[string][]string{}}); err != nil {
		t.Fatalf("clearing nameserverPolicy: %v", err)
	}
	cleared, err := loadAppStoreDNSPolicyAt(store, "p-active")
	if err != nil {
		t.Fatalf("loadAppStoreDNSPolicyAt: %v", err)
	}
	if len(cleared.NameserverPolicy) != 0 || len(cleared.FakeIPFilter) != 1 {
		t.Fatalf("cleared policy = %+v", cleared)
	}
	entries = appStoreRawEntries(t, store)
	patch, err = appStorePatchObject(appStoreEntryOf(t, entries, "p-active"))
	if err != nil {
		t.Fatal(err)
	}
	if string(patch["tun"]) != `{"enable":true}` {
		t.Errorf("clearing the policy dropped tun: %s", patch["tun"])
	}
}

func TestAppStoreDNSPolicyDefaultsWhenAbsent(t *testing.T) {
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, appStoreProfilesFile), []byte(`[{"id":"p","label":"P","order":0}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := loadAppStoreDNSPolicyAt(store, "p")
	if err != nil {
		t.Fatalf("loadAppStoreDNSPolicyAt: %v", err)
	}
	if policy.NameserverPolicy == nil || len(policy.NameserverPolicy) != 0 {
		t.Errorf("nameserverPolicy = %v", policy.NameserverPolicy)
	}
	if policy.FakeIPFilter == nil || len(policy.FakeIPFilter) != 0 {
		t.Errorf("fakeIPFilter = %v", policy.FakeIPFilter)
	}
	rules, err := loadAppStoreRulesAt(store, "p")
	if err != nil {
		t.Fatalf("loadAppStoreRulesAt: %v", err)
	}
	if rules.AppendRules == nil || rules.PrependRules || rules.PatchJSON != "" {
		t.Errorf("rules = %+v", rules)
	}
	if _, err := loadAppStoreRulesAt(store, "nope"); !errors.Is(err, errAppStoreProfileMissing) {
		t.Errorf("unknown id error = %v", err)
	}
	if _, err := loadAppStoreRulesAt(t.TempDir(), "p"); !errors.Is(err, errAppStoreIndexMissing) {
		t.Errorf("missing index error = %v", err)
	}
}

func TestAppStoreDNSValidation(t *testing.T) {
	for name, policy := range map[string]map[string][]string{
		"empty domain":  {"": {"1.1.1.1"}},
		"long domain":   {strings.Repeat("a", appStoreMaximumDomainBytes+1): {"1.1.1.1"}},
		"bare hostname": {"+.example.com": {"dns.example.com"}},
		"empty server":  {"+.example.com": {""}},
		"long server":   {"+.example.com": {"https://" + strings.Repeat("a", appStoreMaximumNameserverBytes)}},
	} {
		if err := validateAppStoreNameserverPolicy(policy); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	if err := validateAppStoreNameserverPolicy(map[string][]string{
		"+.example.com": {"1.1.1.1", "tls://dns.example", "quic://dns.example", "h3://dns.example", "dhcp://en0"},
	}); err != nil {
		t.Errorf("valid nameservers were rejected: %v", err)
	}
	if err := validateAppStoreDomains([]string{"+.example.com", "geosite:cn"}); err != nil {
		t.Errorf("valid fake-ip-filter entries were rejected: %v", err)
	}
}

func TestAppStoreRoutesAnswerTheAppSocket(t *testing.T) {
	store := appStoreFixture(t)
	socket := liveControlPlane(t, controllerConfig(t, "127.0.0.1:"+freeLoopbackPort(t)))
	client := unixHTTPClient(socket)
	base := "http://unix/clash/v1/app/profiles"

	code, body := requestOver(t, client, http.MethodGet, base, "", "", nil)
	var index struct {
		Active struct {
			ProfileID string `json:"profileID"`
			Revision  string `json:"revision"`
		} `json:"active"`
		Profiles []appStoreProfileSummary `json:"profiles"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &index) != nil || index.Active.ProfileID != "p-active" || len(index.Profiles) != 2 {
		t.Fatalf("GET profiles: %d %s", code, body)
	}

	code, body = requestOver(t, client, http.MethodGet, base+"/no-such-profile/rules", "", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("GET rules for an unknown id: %d %s", code, body)
	}

	update := []byte(`{"prependRules":false,"appendRules":["DOMAIN-SUFFIX,x,DIRECT"]}`)
	code, body = requestOver(t, client, http.MethodPut, base+"/p-active/rules", "", "application/json", update)
	if code != http.StatusNoContent {
		t.Fatalf("PUT rules: %d %s", code, body)
	}
	code, body = requestOver(t, client, http.MethodGet, base+"/p-active/rules", "", "", nil)
	var rules appStoreRules
	if code != http.StatusOK || json.Unmarshal(body, &rules) != nil || rules.PrependRules || len(rules.AppendRules) != 1 || rules.AppendRules[0] != "DOMAIN-SUFFIX,x,DIRECT" {
		t.Fatalf("GET rules: %d %s", code, body)
	}
	before, err := os.ReadFile(filepath.Join(store, appStoreProfilesFile))
	if err != nil {
		t.Fatal(err)
	}
	code, body = requestOver(t, client, http.MethodPut, base+"/p-active/rules", "", "application/json",
		[]byte(`{"prependRules":true,"appendRules":["DOMAIN,a,\nDIRECT"]}`))
	if code != http.StatusBadRequest {
		t.Fatalf("PUT an invalid rule: %d %s", code, body)
	}
	after, err := os.ReadFile(filepath.Join(store, appStoreProfilesFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused PUT changed profiles.json")
	}

	code, body = requestOver(t, client, http.MethodGet, base+"/p-active/dns-policy", "", "", nil)
	var policy appStoreDNSPolicy
	if code != http.StatusOK || json.Unmarshal(body, &policy) != nil || policy.NameserverPolicy["+.didichuxing.com"][0] != "10.78.226.116" {
		t.Fatalf("GET dns-policy: %d %s", code, body)
	}
	code, body = requestOver(t, client, http.MethodPut, base+"/p-active/dns-policy", "", "application/json",
		[]byte(`{"nameserverPolicy":{"+.example.com":["1.1.1.1"]}}`))
	if code != http.StatusNoContent {
		t.Fatalf("PUT dns-policy: %d %s", code, body)
	}
	code, body = requestOver(t, client, http.MethodPut, base+"/p-active/dns-policy", "", "application/json",
		[]byte(`{"nameserverPolicy":{"+.example.com":["not an address"]}}`))
	if code != http.StatusBadRequest {
		t.Fatalf("PUT an invalid nameserver: %d %s", code, body)
	}
}

func TestAppStoreRefusesOtherSocketsAndMissingIndex(t *testing.T) {
	recorder := &appStoreRecorder{}
	request, err := mhttp.NewRequest(http.MethodGet, "http://127.0.0.1:9090/clash/v1/app/profiles", nil)
	if err != nil {
		t.Fatal(err)
	}
	serveAppProfiles(recorder, request)
	if recorder.code != http.StatusNotFound {
		t.Errorf("a TCP request got HTTP %d", recorder.code)
	}

	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	socket := liveControlPlane(t, controllerConfig(t, "127.0.0.1:"+freeLoopbackPort(t)))
	code, body := requestOver(t, unixHTTPClient(socket), http.MethodGet, "http://unix/clash/v1/app/profiles", "", "", nil)
	if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "has not published its profile index yet") {
		t.Fatalf("GET profiles without an index: %d %s", code, body)
	}
	if err := os.MkdirAll(filepath.Join(home, appStoreDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, appStoreDirectoryName, appStoreProfilesFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body = requestOver(t, unixHTTPClient(socket), http.MethodGet, "http://unix/clash/v1/app/profiles", "", "", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("GET profiles with a broken index: %d %s", code, body)
	}
}

type appStoreRecorder struct {
	header mhttp.Header
	code   int
	body   bytes.Buffer
}

func (r *appStoreRecorder) Header() mhttp.Header {
	if r.header == nil {
		r.header = mhttp.Header{}
	}
	return r.header
}

func (r *appStoreRecorder) Write(payload []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(payload)
}

func (r *appStoreRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}

func TestAppStoreCapabilityIsAdvertised(t *testing.T) {
	found := false
	for _, capability := range controllerCapabilities {
		found = found || capability == "app-store-v1"
	}
	if !found {
		t.Errorf("controllerCapabilities lacks app-store-v1: %v", controllerCapabilities)
	}
}
