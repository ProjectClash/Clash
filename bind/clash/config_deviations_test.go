package clash

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/http/httptest"
)

func TestDeviationReportCoversAllThreeCategoriesFromWhatTheUserWrote(t *testing.T) {
	const document = `
tproxy-port: 7895
redir-port: 7896
ntp:
  enable: true
  write-to-system: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations := configDeviationsForDocument(t, document)

	byField := make(map[string]configDeviation, len(deviations))
	for _, deviation := range deviations {
		if _, duplicate := byField[deviation.Field]; duplicate {
			t.Errorf("%s reported twice", deviation.Field)
		}
		byField[deviation.Field] = deviation
	}

	for field, want := range map[string]string{
		"redir-port":          deviationUnavailable,
		"tproxy-port":         deviationUnavailable,
		"ntp.write-to-system": deviationForced,
	} {
		deviation, reported := byField[field]
		if !reported {
			t.Errorf("%s was changed but is not reported; the user has no way to learn it", field)
			continue
		}
		if deviation.Category != want {
			t.Errorf("%s category = %q, want %q", field, deviation.Category, want)
		}
		if deviation.Given == "" {
			t.Errorf("%s does not carry what the user wrote; a report the reader cannot match "+
				"against their own file is not addressable", field)
		}
		if deviation.Effective == "" {
			t.Errorf("%s does not say what happens instead", field)
		}
		if deviation.Source == "" {
			t.Errorf("%s carries no citation. Every deviation owes either an Apple source or a "+
				"measurement of ours -- that rule is what this whole batch exists to enforce", field)
		}
	}

	want := map[string]bool{
		"redir-port": true, "tproxy-port": true, "ntp.write-to-system": true,
		"dns.enable": true, "find-process-mode": true, "unified-delay": true, "profile.store-fake-ip": true,
		"tun.stack": true,
	}
	for field := range byField {
		if !want[field] {
			t.Errorf("%s is reported for a document that does not deviate in it", field)
		}
	}
	if len(deviations) != len(want) {
		t.Errorf("reported %d deviations, want %d: %v", len(deviations), len(want), fieldsOf(deviations))
	}
}

func TestASilentConfigurationReportsOnlyWhatItStillChanges(t *testing.T) {
	const silent = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	reported := map[string]bool{}
	for _, deviation := range configDeviationsForDocument(t, silent) {
		reported[deviation.Field] = true
	}
	silentlyChanged := map[string]bool{
		"dns.enable": true, "find-process-mode": true, "unified-delay": true, "profile.store-fake-ip": true,
		"tun.stack": true,
	}
	for field := range reported {
		if !silentlyChanged[field] {
			t.Errorf("%s is reported for a reader who wrote nothing and whose behaviour it does "+
				"not change", field)
		}
	}
	if len(reported) != len(silentlyChanged) {
		t.Errorf("silent configuration reported %d deviations, want %d: %v",
			len(reported), len(silentlyChanged), reported)
	}
}

func TestRecoverabilityDistinguishesAPlatformWallFromOurChoice(t *testing.T) {
	const document = `
tproxy-port: 7895
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	for _, deviation := range configDeviationsForDocument(t, document) {
		if deviation.Recoverable && deviation.Category != deviationForced {
			t.Errorf("%s is %s yet claims editing the configuration alone restores it",
				deviation.Field, deviation.Category)
		}
		if deviation.Recoverable && deviation.Alternative == "" {
			t.Errorf("%s says it is recoverable without saying how", deviation.Field)
		}
		switch deviation.Field {
		case "tproxy-port":
			if deviation.Alternative != "" {
				t.Errorf("tproxy-port offers an alternative (%q), but upstream's own "+
					"setsockopt_other.go answers 'not supported on current platform' and no "+
					"Apple facility replaces it", deviation.Alternative)
			}
		case "redir-port":
			if deviation.Alternative != "" {
				t.Errorf("redir-port offers an alternative (%q); nothing on Apple replaces it", deviation.Alternative)
			}
			if !strings.Contains(deviation.Reason+deviation.Source+deviation.Mechanism, "/dev/pf") {
				t.Error("redir-port does not cite the platform fact that justifies it")
			}
		}
	}
}

func TestDeviationRouteServesWhatTheRunningCoreDecided(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })

	publishDeviations(deviationEntryStart, "port: 7890\n", []configDeviation{{
		Field: "port", Given: "7890", Effective: "no listener is opened",
		Category: deviationStripped, Reason: "product decision", Source: "proxy_share.go:313",
		Recoverable: true,
	}})

	recorder := httptest.NewRecorder()
	serveConfigDeviations(recorder, httptest.NewRequest("GET", "/clash/v1/deviations", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	var body struct {
		SchemaVersion int               `json:"schemaVersion"`
		Deviations    []configDeviation `json:"deviations"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %s", recorder.Body.String())
	}
	if len(body.Deviations) != 1 || body.Deviations[0].Field != "port" {
		t.Fatalf("endpoint did not serve the published list: %s", recorder.Body.String())
	}
	if body.SchemaVersion == 0 {
		t.Error("no schema version; a client cannot tell an empty list from an older core that " +
			"never published one")
	}
}

func TestDeviationRouteAnswersBeforeAnythingIsPublished(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	publishedDeviations.Store(nil)

	recorder := httptest.NewRecorder()
	serveConfigDeviations(recorder, httptest.NewRequest("GET", "/clash/v1/deviations", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d", recorder.Code)
	}
	if body := recorder.Body.String(); !json.Valid([]byte(body)) {
		t.Fatalf("response is not JSON: %s", body)
	}
	var body struct {
		Deviations []configDeviation `json:"deviations"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	if body.Deviations == nil {
		t.Error("deviations is null before Start; an empty array is the honest answer")
	}
}

func configDeviationsForDocument(t *testing.T, document string) []configDeviation {
	t.Helper()
	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return deviations
}

func fieldsOf(deviations []configDeviation) []string {
	fields := make([]string, 0, len(deviations))
	for _, deviation := range deviations {
		fields = append(fields, deviation.Field)
	}
	return fields
}

func TestDeviationsFromSilenceAreReportedToo(t *testing.T) {
	const silent = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	byField := make(map[string]configDeviation)
	for _, deviation := range configDeviationsForDocument(t, silent) {
		byField[deviation.Field] = deviation
	}

	for _, field := range []string{"dns.enable", "find-process-mode"} {
		deviation, reported := byField[field]
		if !reported {
			t.Errorf("%s is overwritten even when unwritten, and is not reported; a silent "+
				"configuration behaves differently from mihomo's and nobody is told", field)
			continue
		}
		if deviation.Category != deviationForced {
			t.Errorf("%s category = %q, want %q", field, deviation.Category, deviationForced)
		}
		if deviation.Given == "" {
			t.Errorf("%s must still say what mihomo would have used; the reader wrote nothing, "+
				"so the only useful baseline is upstream's default", field)
		}
	}
}

func TestForcingAValueUpstreamAlreadyDefaultsToIsNotADeviation(t *testing.T) {
	const silent = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	for _, deviation := range configDeviationsForDocument(t, silent) {
		if deviation.Field == "ntp.write-to-system" {
			t.Error("ntp.write-to-system is reported for a reader who never wrote it, but " +
				"upstream's own default is false as well -- nothing differs")
		}
	}
}

func TestRuntimeParseRepublishesOnEveryStartAndReload(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	publishedDeviations.Store(nil)

	const withPort = `
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, _, err := parseConfigForIOSRuntime(withPort, true, deviationEntryStart); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reportsField(loadPublishedDeviations(), "redir-port") {
		t.Fatalf("a Start-path parse did not publish: %v", fieldsOf(loadPublishedDeviations()))
	}

	const withoutPort = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, _, err := parseConfigForIOSRuntime(withoutPort, true, deviationEntryReload); err != nil {
		t.Fatalf("reload parse: %v", err)
	}
	if reportsField(loadPublishedDeviations(), "redir-port") {
		t.Errorf("redir-port is still reported after a reload that removed it: %v", fieldsOf(loadPublishedDeviations()))
	}
}

func TestValidatingACandidateDoesNotOverwriteTheRunningReport(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })

	publishDeviations(deviationEntryStart, "running: []\n", []configDeviation{{Field: "running-marker", Category: deviationStripped}})

	const candidate = `
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	if _, err := parseConfigForIOS(candidate, true); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reportsField(loadPublishedDeviations(), "running-marker") {
		t.Errorf("validating a candidate replaced the running core's report: %v",
			fieldsOf(loadPublishedDeviations()))
	}
}

func reportsField(deviations []configDeviation, field string) bool {
	for _, deviation := range deviations {
		if deviation.Field == field {
			return true
		}
	}
	return false
}

func TestCredentialBearingFieldsNeverRenderTheirValue(t *testing.T) {
	const document = `
secret: hunter2
authentication:
  - "alice:correct-horse"
tls:
  private-key: |
    -----BEGIN PRIVATE KEY-----
    NOTAREALKEY
tuic-server:
  enable: true
  token:
    - deadbeefdeadbeef
  users:
    bob: swordfish
ss-config: "ss://chacha20-ietf-poly1305:tell-nobody@:8388"
vmess-config: "vmess://11111111-2222-3333-4444-555555555555"
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	secrets := []string{
		"hunter2", "correct-horse", "NOTAREALKEY", "deadbeefdeadbeef",
		"swordfish", "tell-nobody", "11111111-2222-3333-4444-555555555555",
	}
	deviations := configDeviationsForDocument(t, document)
	if len(deviations) == 0 {
		t.Fatal("nothing was reported, so this test proves nothing")
	}
	for _, deviation := range deviations {
		rendered := deviation.Field + "|" + deviation.Given + "|" + deviation.Effective + "|" +
			deviation.Reason + "|" + deviation.Source + "|" + deviation.Alternative
		for _, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Errorf("%s renders a credential the user supplied; this goes to an HTTP "+
					"response and to a log line on disk", deviation.Field)
			}
		}
	}
}

func TestNonCredentialFieldsStillShowWhatTheUserWrote(t *testing.T) {
	const document = `
tproxy-port: 7895
redir-port: 7896
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	for _, deviation := range configDeviationsForDocument(t, document) {
		switch deviation.Field {
		case "redir-port":
			if deviation.Given != "7896" {
				t.Errorf("redir-port given = %q, want the value the user wrote", deviation.Given)
			}
		case "tproxy-port":
			if deviation.Given != "7895" {
				t.Errorf("tproxy-port given = %q, want the value the user wrote", deviation.Given)
			}
		}
	}
}
