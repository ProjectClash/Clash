package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTheExportersUnsetPlaceholderIsNotReadAsAValue(t *testing.T) {
	read := func(t *testing.T, link string) map[string]any {
		t.Helper()
		box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Fatalf("%s refused: %+v %+v", link, report.Skipped, report.Skipped)
		}
		return report.Proxies[0]
	}

	for _, unset := range []struct{ label, link, field string }{
		{"snell version", "snell://pw@example.invalid:443?version=none#s", "version"},
		{"hysteria protocol", "hysteria://example.invalid:443?auth=p&upmbps=10&downmbps=20&protocol=none#h", "protocol"},
		{"tuic congestion control", "tuic://11111111-2222-3333-4444-555555555555:p@example.invalid:443?congestion_control=none#t", "congestion-controller"},
	} {
		t.Run(unset.label, func(t *testing.T) {
			proxy := read(t, unset.link)
			value, present := proxy[unset.field]
			if present && strings.EqualFold(anyString(value), "none") {
				encoded, _ := json.Marshal(proxy)
				t.Fatalf("%s reached the kernel as the literal word: %s", unset.field, encoded)
			}
		})
	}

	t.Run("vless encryption none is a real value", func(t *testing.T) {
		proxy := read(t, "vless://11111111-2222-3333-4444-555555555555@example.invalid:443?encryption=none#v")
		if got := anyString(proxy["encryption"]); got != "none" {
			t.Fatalf("encryption = %q -- a legitimate value was blanked as a placeholder", got)
		}
	})
}

func TestTheExporterOmitsWhatItConsidersImplicit(t *testing.T) {
	t.Run("mieru transport is recovered", func(t *testing.T) {
		box, err := InspectProxyPayloadForIOS([]byte("mierus://user:sample@e.invalid?port=443&profile=p"), "singleNode")
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Fatalf("refused: %+v %+v", report.Skipped, report.Skipped)
		}
		if got := anyString(report.Proxies[0]["transport"]); got != "TCP" {
			t.Fatalf("transport = %q, want TCP", got)
		}
	})

	t.Run("an empty snell key is reported, not invented", func(t *testing.T) {
		box, err := InspectProxyPayloadForIOS(
			[]byte("snell://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo@198.51.100.10:443?version=4#n"), "singleNode")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 0 {
			encoded, _ := json.Marshal(report.Proxies[0])
			t.Fatalf("imported a node with an invented PSK: %s", encoded)
		}
		if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Message, "PSK") {
			t.Fatalf("the refusal does not name the missing key: %+v", report.Skipped)
		}
	})
}

func TestTheExporterMovesCredentialsAndWeFollowThem(t *testing.T) {
	read := func(t *testing.T, link string) map[string]any {
		t.Helper()
		box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		var report proxyImportReport
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatalf("report: %v", err)
		}
		if len(report.Proxies) != 1 {
			t.Fatalf("%s refused: %+v %+v", link, report.Skipped, report.Skipped)
		}
		return report.Proxies[0]
	}

	t.Run("mieru userinfo is decoded", func(t *testing.T) {
		proxy := read(t, "mierus://dTpw:@example.invalid?port=2999&profile=p")
		if got := anyString(proxy["username"]); got != "u" {
			t.Errorf("username = %q, want u -- the encoded pair was taken whole", got)
		}
		if got := anyString(proxy["password"]); got != "p" {
			t.Errorf("password = %q, want p", got)
		}
	})

	t.Run("socks5h is recognised", func(t *testing.T) {
		proxy := read(t, "socks5h://dXNlcjpwYXNz@example.invalid:1080#s5h")
		if got := anyString(proxy["type"]); got != "socks5" {
			t.Errorf("type = %q, want socks5", got)
		}
		if got := anyString(proxy["password"]); got != "pass" {
			t.Errorf("password = %q, want pass", got)
		}
	})
}
