package clash

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAProxyImportSummaryIsTheReportWithoutItsNodes(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "  - {name: n%d, type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "  - {name: bad%d, type: ss, server: b%d.example.net, port: 8388, cipher: aes-128-gcm}\n", i, i)
	}
	payload := []byte(b.String())
	for _, c := range []struct {
		full, summary func([]byte, string) (*StringBox, error)
	}{{InspectProxyPayloadForIOS, InspectProxyPayloadSummaryForIOS}, {ReadProxyPayloadForIOS, ReadProxyPayloadSummaryForIOS}} {
		fullBox, err := c.full(payload, "subscriptionBody")
		if err != nil {
			t.Fatal(err)
		}
		summaryBox, err := c.summary(payload, "subscriptionBody")
		if err != nil {
			t.Fatal(err)
		}
		var full proxyImportReport
		var summary proxyImportSummary
		if json.Unmarshal([]byte(fullBox.Value), &full) != nil || json.Unmarshal([]byte(summaryBox.Value), &summary) != nil {
			t.Fatal("undecodable")
		}
		if summary.Count != len(full.Proxies) || summary.SkippedCount != len(full.Skipped) || summary.NotHonouredCount != len(full.NotHonoured) ||
			summary.Format != full.Format || summary.Context != full.Context || len(summary.Skipped) != min(len(full.Skipped), 50) {
			t.Fatalf("summary %+v of a report with %d nodes, %d skipped", summary, len(full.Proxies), len(full.Skipped))
		}
		for i := range summary.Skipped {
			if fmt.Sprint(summary.Skipped[i]) != fmt.Sprint(full.Skipped[i]) {
				t.Fatalf("skip %d: %+v, report %+v", i, summary.Skipped[i], full.Skipped[i])
			}
		}
		if strings.Contains(summaryBox.Value, "n119") {
			t.Fatal("the summary carries nodes")
		}
	}
	if _, err := InspectProxyPayloadSummaryForIOS(nil, "nodeBundle"); err == nil {
		t.Fatal("an empty payload is refused as the report refuses it")
	}
}

func TestAPayloadHeldOpenReadsAsTheWholeReportInPages(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 57; i++ {
		fmt.Fprintf(&b, "  - {name: \"n<%d>\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	payload := []byte(b.String())
	whole, err := ReadProxyPayloadForIOS(payload, "subscriptionBody")
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		Proxies    []json.RawMessage
		Identities []string
	}
	_ = json.Unmarshal([]byte(whole.Value), &want)
	view, err := OpenProxyPayloadForIOS(payload, "subscriptionBody")
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	var proxies []json.RawMessage
	var identities []string
	for offset := int32(0); ; offset += 10 {
		var page struct {
			Total      int
			Proxies    []json.RawMessage
			Identities []string
		}
		if err := json.Unmarshal([]byte(view.PageJSON(offset, 10)), &page); err != nil || page.Total != 57 {
			t.Fatalf("page: %v, total %d", err, page.Total)
		}
		proxies, identities = append(proxies, page.Proxies...), append(identities, page.Identities...)
		if int(offset)+10 >= page.Total {
			break
		}
	}
	if len(proxies) != len(want.Proxies) || strings.Join(identities, ",") != strings.Join(want.Identities, ",") {
		t.Fatalf("%d nodes in pages, %d whole", len(proxies), len(want.Proxies))
	}
	for i := range proxies {
		if string(proxies[i]) != string(want.Proxies[i]) {
			t.Fatalf("node %d: %s, whole %s", i, proxies[i], want.Proxies[i])
		}
	}
	summary, _ := ReadProxyPayloadSummaryForIOS(payload, "subscriptionBody")
	if view.SummaryJSON() != summary.Value {
		t.Fatalf("summary %s, want %s", view.SummaryJSON(), summary.Value)
	}
}
