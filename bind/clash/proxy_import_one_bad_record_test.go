package clash

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOneUnreadableRecordDoesNotCostTheRestOfTheDocument(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		reason  string
	}{
		{
			name: "a surge line naming a field this build does not map",
			payload: "[Proxy]\n" +
				"A = trojan, a.example, 443, password=pw\n" +
				"B = trojan, b.example, 443, password=pw, clash-unknown=1\n" +
				"C = trojan, c.example, 443, password=pw\n",
			reason: "clash-unknown",
		},
		{
			name: "a surge line that is not a proxy line at all",
			payload: "[Proxy]\n" +
				"A = trojan, a.example, 443, password=pw\n" +
				"BBBB\n" +
				"C = trojan, c.example, 443, password=pw\n",
			reason: "BBBB",
		},
		{
			name: "a sing-box outbound with no server_port",
			payload: `{"outbounds":[` +
				`{"type":"trojan","tag":"A","server":"a.example","server_port":443,"password":"pw"},` +
				`{"type":"trojan","tag":"B","server":"b.example","password":"pw"},` +
				`{"type":"trojan","tag":"C","server":"c.example","server_port":443,"password":"pw"}]}`,
			reason: "server_port",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "nodeBundle")
			if err != nil {
				t.Fatalf("one unreadable record cost the whole document: %v", err)
			}
			var report struct {
				Proxies []map[string]any `json:"proxies"`
				Skipped []struct {
					Message string `json:"message"`
				} `json:"skipped"`
			}
			if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
				t.Fatalf("decode: %v", err)
			}
			names := make([]string, 0, len(report.Proxies))
			for _, proxy := range report.Proxies {
				name, _ := proxy["name"].(string)
				names = append(names, name)
			}
			if len(names) != 2 || names[0] != "A" || names[1] != "C" {
				t.Fatalf("the readable records did not survive: %v", names)
			}
			if len(report.Skipped) != 1 {
				t.Fatalf("expected one skip, got %d: %#v", len(report.Skipped), report.Skipped)
			}
			if !strings.Contains(report.Skipped[0].Message, test.reason) {
				t.Fatalf("the skip does not say what was wrong with the record: %q", report.Skipped[0].Message)
			}
		})
	}
}

func TestADocumentWhoseRecordsAllFailedStillReportsWhy(t *testing.T) {
	payload := "[Proxy]\nAAAA\nBBBB\n"
	box, err := InspectProxyPayloadForIOS([]byte(payload), "nodeBundle")
	if err != nil {
		t.Fatalf("a document of unreadable records produced no report at all: %v", err)
	}
	var report struct {
		Proxies []map[string]any `json:"proxies"`
		Skipped []struct {
			Message string `json:"message"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(report.Proxies) != 0 || len(report.Skipped) != 2 {
		t.Fatalf("expected two skips and no nodes: %#v", report)
	}
}
