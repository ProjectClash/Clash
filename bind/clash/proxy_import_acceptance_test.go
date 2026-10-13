package clash

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func inspectProxyPayloadReport(t *testing.T, payload, context string) proxyImportReport {
	t.Helper()
	box, err := InspectProxyPayloadForIOS([]byte(payload), context)
	if err != nil {
		t.Fatalf("InspectProxyPayloadForIOS(%s) returned an error instead of a report: %v", context, err)
	}
	var report proxyImportReport
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report
}

func TestAnUnmappedQueryKeyIsNamedAndTheNodeStillArrives(t *testing.T) {
	for name, link := range map[string]string{
		"with value":  "trojan://secret@example.invalid:443?peer=sni.example.invalid&clashUnmappedField=1#node",
		"empty value": "trojan://secret@example.invalid:443?peer=sni.example.invalid&clashUnmappedField=#node",
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, link, "nodeBundle")
			if len(report.Proxies) != 1 {
				t.Fatalf("an unmapped key cost the node: %+v", report)
			}
			if len(report.Skipped) != 0 {
				t.Fatalf("the record was skipped over one unmapped key: %+v", report.Skipped)
			}
			if len(report.NotHonoured) != 1 ||
				!strings.Contains(report.NotHonoured[0].Message, "clashUnmappedField") {
				t.Fatalf("the unmapped key was dropped without saying so: %+v", report.NotHonoured)
			}
		})
	}
}

func TestValidateProxyShareLinkQueryFieldsIsFailClosedWhenAsked(t *testing.T) {
	capability := proxyImportCapability{Scheme: "trojan", CanonicalType: "trojan", Status: proxyImportSupported}
	if _, err := validateProxyShareLinkQueryFields("trojan://secret@example.invalid:443?peer=sni.example.invalid", capability, false); err != nil {
		t.Fatalf("a mapped key was refused: %v", err)
	}
	for _, link := range []string{
		"trojan://secret@example.invalid:443?clashUnmappedField=1",
		"trojan://secret@example.invalid:443?clashUnmappedField=",
	} {
		if _, err := validateProxyShareLinkQueryFields(link, capability, false); err == nil {
			t.Fatalf("an unmapped key passed the ledger: %s", link)
		}
	}
}

func TestSingleNodeFailureCarriesTheReason(t *testing.T) {
	for name, testCase := range map[string]struct{ payload, wantCode string }{
		"unknown scheme": {"clashnotascheme://x@example.invalid:443#n", "unknownScheme"},

		"recognized but unsupported scheme": {"juicity://x@example.invalid:443#n", proxyImportCoreUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, testCase.payload, "singleNode")
			issues := report.Skipped
			if len(issues) != 1 {
				t.Fatalf("want exactly one issue, got %d: %+v", len(issues), report)
			}
			if issues[0].Code != testCase.wantCode {
				t.Fatalf("code %q, want %q", issues[0].Code, testCase.wantCode)
			}
			if len(report.Proxies) != 0 {
				t.Fatalf("a failed single-node import still produced proxies: %v", report.Proxies)
			}
		})
	}
}

func TestProxyPayloadSizeRefusalsNameWhatIsWrong(t *testing.T) {
	asTunnelProcess(t)
	if _, err := InspectProxyPayloadForIOS(nil, "singleNode"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("the empty-payload refusal does not say it is empty: %v", err)
	}
	oversized := make([]byte, maximumProviderResourceBytes+1)
	_, err := InspectProxyPayloadForIOS(oversized, "singleNode")
	if err == nil {
		t.Fatal("an oversized payload was accepted")
	}
	for _, want := range []string{fmt.Sprint(maximumProviderResourceBytes), fmt.Sprint(len(oversized))} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the oversize refusal %q carries neither the limit nor the size (%s)", err.Error(), want)
		}
	}
}

func TestMieruStandardURLIsRecognizedNotUnknown(t *testing.T) {
	report := inspectProxyPayloadReport(t, "mieru://x@198.51.100.30:443#M", "nodeBundle")
	if len(report.Skipped) != 1 {
		t.Fatalf("mieru:// is not reported as skipped: %+v", report)
	}
	if report.Skipped[0].Code != proxyImportCoreUnsupported {
		t.Fatalf("code %q, want %q -- mieru:// is recognized, not unknown",
			report.Skipped[0].Code, proxyImportCoreUnsupported)
	}
}

func TestDuplicateNamesFollowUpstreamUniqueNameFormat(t *testing.T) {
	payload := strings.Join([]string{
		"trojan://a@example.invalid:443#Site",
		"trojan://b@example.invalid:443#Site",
		"trojan://c@example.invalid:443#Site",
	}, "\n")
	report := inspectProxyPayloadReport(t, payload, "nodeBundle")
	want := []string{"Site", "Site-01", "Site-02"}
	if len(report.Proxies) != len(want) {
		t.Fatalf("want %d proxies, got %d: %+v", len(want), len(report.Proxies), report)
	}
	for index, wanted := range want {
		if name, _ := report.Proxies[index]["name"].(string); name != wanted {
			t.Fatalf("proxy %d is named %q, want %q", index, name, wanted)
		}
	}
}

func TestCapabilityDocumentCarriesThePasteRole(t *testing.T) {
	var document proxyImportCapabilitiesDocument
	if err := json.Unmarshal([]byte(ProxyImportCapabilitiesForIOS().Value), &document); err != nil {
		t.Fatalf("decode capability document: %v", err)
	}
	roles := make(map[string]string, len(document.Schemes))
	for _, capability := range document.Schemes {
		if capability.PasteRole == "" {
			t.Fatalf("scheme %q carries no paste role", capability.Scheme)
		}
		roles[capability.Scheme] = capability.PasteRole
	}
	for scheme, want := range map[string]string{
		"sub":     proxyImportPasteWrapper,
		"http":    proxyImportPasteSubscription,
		"https":   proxyImportPasteSubscription,
		"trojan":  proxyImportPasteNode,
		"juicity": proxyImportPasteNode,
		"mierus":  proxyImportPasteNode,
	} {
		if roles[scheme] != want {
			t.Fatalf("scheme %q has paste role %q, want %q", scheme, roles[scheme], want)
		}
	}
}

func TestShareLinkIssuesAreLocatableInTheOriginalText(t *testing.T) {
	payload := strings.Join([]string{
		"trojan://a@example.invalid:443#First",
		"clashnotascheme://b@example.invalid:443#Second",
		"trojan://c@example.invalid:443#Third",
	}, "\n")
	report := inspectProxyPayloadReport(t, payload, "nodeBundle")
	if len(report.Skipped) != 1 {
		t.Fatalf("want one rejected record, got %d: %+v", len(report.Skipped), report.Skipped)
	}
	issue := report.Skipped[0]
	if issue.Line != 2 {
		t.Fatalf("rejected record reports line %d, want 2", issue.Line)
	}
	if want := strings.Index(payload, "clashnotascheme"); issue.Offset != want {
		t.Fatalf("rejected record reports offset %d, want %d", issue.Offset, want)
	}
}

func TestHysteria2PortHoppingSurvivesEverySpelling(t *testing.T) {
	for name, testCase := range map[string]struct{ link, wantPorts string }{
		"authority list":  {"hysteria2://pw@example.invalid:443,5000-6000#N", "443,5000-6000"},
		"authority range": {"hysteria2://pw@example.invalid:40000-50000#N", "40000-50000"},
		"query mport":     {"hysteria2://pw@example.invalid:443?mport=40000-50000#N", "40000-50000"},
		"query ports":     {"hysteria2://pw@example.invalid:443?ports=40000-50000#N", "40000-50000"},
	} {
		t.Run(name, func(t *testing.T) {
			report := inspectProxyPayloadReport(t, testCase.link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("want one proxy, got %d: %+v", len(report.Proxies), report)
			}
			if ports, _ := report.Proxies[0]["ports"].(string); ports != testCase.wantPorts {
				t.Fatalf("ports = %q, want %q", ports, testCase.wantPorts)
			}
		})
	}

	report := inspectProxyPayloadReport(t, "hysteria2://pw@example.invalid:443#N", "singleNode")
	if len(report.Proxies) != 1 {
		t.Fatalf("the single-port control stopped working: %+v", report)
	}
	if _, present := report.Proxies[0]["ports"]; present {
		t.Fatalf("a single-port link grew a ports key: %+v", report.Proxies[0])
	}
}

func TestHysteria2PortHoppingMatchesUpstreamFieldForField(t *testing.T) {
	report := inspectProxyPayloadReport(t,
		"hysteria2://letmein@example.invalid:443,5000-6000/?sni=example.invalid#hop", "singleNode")
	if len(report.Proxies) != 1 {
		t.Fatalf("want one proxy, got %d: %+v", len(report.Proxies), report)
	}
	proxy := report.Proxies[0]
	for key, want := range map[string]string{
		"server": "example.invalid",
		"port":   "443",
		"ports":  "443,5000-6000",
	} {
		if got := anyString(proxy[key]); got != want {
			t.Fatalf("%s = %q, want %q (upstream converter_test asserts this)", key, got, want)
		}
	}
}
