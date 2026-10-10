package clash

import (
	"encoding/json"
	"os"
	"testing"
)

type exporterEmittedCorpus struct {
	Records []struct {
		Exported string `json:"exported"`
		Expect   string `json:"expect"`
	} `json:"records"`
}

func TestEveryLineTheExporterEmitsLandsWhereTheCorpusSays(t *testing.T) {
	raw, err := os.ReadFile("testdata/shadowrocket-2.2.90-3378-emitted-corpus.json")
	if err != nil {
		t.Fatalf("read the emitted corpus: %v", err)
	}
	var corpus exporterEmittedCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	if len(corpus.Records) < 30 {
		t.Fatalf("corpus holds %d records -- too few to be the scheme-wide sweep", len(corpus.Records))
	}
	counts := map[string]int{}
	for _, record := range corpus.Records {
		box, err := InspectProxyPayloadForIOS([]byte(record.Exported), "singleNode")
		got := ""
		var report proxyImportReport
		if err != nil {
			got = "rejected"
		} else {
			if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
				t.Fatalf("report: %v", err)
			}
			switch {
			case len(report.Proxies) == 1:
				got = "accepted"
			case len(report.Skipped) > 0 && report.Skipped[0].Code == "coreUnsupported":
				got = "coreUnsupported"
			default:
				got = "rejected"
			}
		}
		counts[got]++
		if got != record.Expect {
			t.Errorf("%s\n  want %s, got %s (rejected=%+v unsupported=%+v)",
				record.Exported, record.Expect, got, report.Skipped, report.Skipped)
		}
	}
	t.Logf("exporter replies: accepted %d / coreUnsupported %d / rejected %d",
		counts["accepted"], counts["coreUnsupported"], counts["rejected"])
}
