package clash

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestNoRealConfigurationIsRefusedAheadOfUpstream(t *testing.T) {
	corpus := realSubscriptionCorpus
	entries, err := os.ReadDir(corpus)
	if err != nil {
		t.Skipf("the real-subscription corpus is not present in this tree: %v", err)
	}

	checked, fired, proxies := 0, 0, 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			document, err := os.ReadFile(filepath.Join(corpus, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			raw, err := config.UnmarshalRawConfig(document)
			if err != nil {
				t.Skipf("not a document this test can judge: %v", err)
			}
			checked++
			proxies += len(raw.Proxy)

			issues := upstreamRefusedOutboundOptions(raw)
			if len(issues) == 0 {
				return
			}
			fired++
			if _, err := config.ParseRawConfig(raw); err == nil {
				t.Errorf("this tree refuses %d option value(s) that mihomo accepts, so a working "+
					"configuration would stop working: %+v", len(issues), issues)
			}
		})
	}

	if checked == 0 {
		t.Fatal("no configuration was judged; the corpus path is wrong and this test proves nothing")
	}
	if proxies == 0 {
		t.Fatal("the corpus was read but carries no outbound the predicate can reach, so a green here " +
			"says nothing about it")
	}

	t.Logf("judged %d real configurations carrying %d outbounds; the predicate fired on %d",
		checked, proxies, fired)
}
