package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

const planNoticeProbeDocument = `mixed-port: 7890
find-process-mode: strict
tun:
  enable: true
  auto-redirect: true
dns:
  enable: true
  nameserver:
    - system
    - 1.1.1.1
proxies: []
rules:
  - PROCESS-NAME,curl,DIRECT
  - MATCH,DIRECT
`

func planNoticesFor(t *testing.T, document, profile string) ([]string, []planNotice) {
	t.Helper()
	box, err := PlanResourcesForProfile(document, profile)
	if err != nil {
		t.Fatalf("%s: %v", profile, err)
	}
	var plan struct {
		Notices           []string     `json:"notices"`
		StructuredNotices []planNotice `json:"structuredNotices"`
	}
	if err := json.Unmarshal([]byte(box.Value), &plan); err != nil {
		t.Fatal(err)
	}
	return plan.Notices, plan.StructuredNotices
}

func kindsOf(notices []planNotice) map[string]int {
	out := map[string]int{}
	for _, n := range notices {
		out[n.Kind]++
	}
	return out
}

func TestPlanNoticesFollowTheProfileTheyAreComputedFor(t *testing.T) {
	_, ios := planNoticesFor(t, planNoticeProbeDocument, RuntimeProfileIOSPacketTunnel)
	_, mac := planNoticesFor(t, planNoticeProbeDocument, RuntimeProfileMacOSPacketTunnel)
	iosKinds, macKinds := kindsOf(ios), kindsOf(mac)

	if iosKinds[planNoticeFindProcessModeForcedOff] != 1 || iosKinds[planNoticeMetadataRulesInert] != 1 {
		t.Fatalf("iOS plan lacks the process notices it owes: %v", iosKinds)
	}
	if macKinds[planNoticeFindProcessModeForcedOff] != 0 || macKinds[planNoticeMetadataRulesInert] != 0 {
		t.Fatalf("macOS plan carries process notices that are false on a macOS packet tunnel: %v", macKinds)
	}
	for name, notices := range map[string][]planNotice{"iOS": ios, "macOS": mac} {
		if kindsOf(notices)[planNoticeDNSSystemResolverStripped] != 1 {
			t.Fatalf("%s plan lacks a packet-tunnel notice that holds on every packet tunnel: %v", name, kindsOf(notices))
		}
		for _, n := range notices {
			if strings.HasPrefix(n.Field, "tun.") {
				t.Fatalf("%s plan reports %s, which reaches upstream as written: %q", name, n.Field, n.Text)
			}
		}
	}
	_, app := planNoticesFor(t, planNoticeProbeDocument, RuntimeProfileMacOSApplication)
	if len(app) != 0 {
		t.Fatalf("the macOS application profile got packet-tunnel notices: %v", kindsOf(app))
	}
}

func TestPlanNoticesNameNoPlatform(t *testing.T) {
	for _, seat := range registryProfiles {
		notices, _ := planNoticesFor(t, planNoticeProbeDocument, seat.name)
		for _, n := range notices {
			for _, word := range []string{"iOS", "macOS", "tvOS", "mihomo", "Apple owns"} {
				if strings.Contains(n, word) {
					t.Errorf("%s: a notice names a platform or the upstream project, which is wrong on two of three platforms and a product-name leak on all: %q", seat.name, n)
				}
			}
		}
	}
}

func TestStructuredNoticesMirrorNoticesAndUseTheVocabulary(t *testing.T) {
	known := map[string]bool{
		planNoticeProviderFetchProxyHonoured: true, planNoticeProviderFetchProxySelfReferential: true,
		planNoticeEgressOverrideStripped:   true,
		planNoticeFindProcessModeForcedOff: true, planNoticeMetadataRulesInert: true,
		planNoticeDNSSystemResolverStripped: true, planNoticeDNSBootstrapReplaced: true,
		planNoticeDNSFragmentUnroutable: true,
	}
	for _, seat := range registryProfiles {
		notices, structured := planNoticesFor(t, planNoticeProbeDocument, seat.name)
		if len(notices) != len(structured) {
			t.Fatalf("%s: %d notices but %d structured rows", seat.name, len(notices), len(structured))
		}
		for i := range notices {
			if notices[i] != structured[i].Text {
				t.Fatalf("%s: row %d text differs: %q vs %q", seat.name, i, notices[i], structured[i].Text)
			}
			if !known[structured[i].Kind] {
				t.Fatalf("%s: row %d has a kind outside the vocabulary: %q", seat.name, i, structured[i].Kind)
			}
			if structured[i].Field == "" {
				t.Fatalf("%s: row %d has no field to key on: %+v", seat.name, i, structured[i])
			}
		}
	}
}

func TestPlanResourcesForIOSIsTheIOSProfile(t *testing.T) {
	legacy, err := PlanResourcesForIOS(planNoticeProbeDocument)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := PlanResourcesForProfile(planNoticeProbeDocument, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Value != explicit.Value {
		t.Fatalf("PlanResourcesForIOS and PlanResourcesForProfile(iOS) differ:\n%s\n%s", legacy.Value, explicit.Value)
	}
}
