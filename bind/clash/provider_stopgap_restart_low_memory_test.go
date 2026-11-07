//go:build with_low_memory

package clash

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)

func TestAStopgapRunsAgainBesideALargerWaitingPayloadAfterARestart(t *testing.T) {
	for _, c := range []struct{ gone, refused bool }{{false, false}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("product gone %v, judge refuses %v", c.gone, c.refused), func(t *testing.T) { stopgapRestart(t, c.gone, c.refused) })
	}
}

func stopgapRestart(t *testing.T, productGone, judgeRefuses bool) {
	settle, backoff, poll, first := providerRefreshSettleDelay, providerRefreshMinimumBackoff, providerRefreshPoll, providerRefreshFirstLoadMinimum
	providerRefreshSettleDelay, providerRefreshMinimumBackoff, providerRefreshPoll = 0, 50*time.Millisecond, 20*time.Millisecond
	providerRefreshFirstLoadMinimum = 50 * time.Millisecond
	t.Cleanup(func() {
		providerRefreshSettleDelay, providerRefreshMinimumBackoff, providerRefreshPoll, providerRefreshFirstLoadMinimum = settle, backoff, poll, first
	})
	setup := testOptions(t)
	setup.RuntimeProfile = RuntimeProfileIOSPacketTunnel
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)

	text := func(prefix string, limit int) string {
		var b strings.Builder
		for j := 0; ; j++ {
			line := fmt.Sprintf("%s-host-%06d.example.com\n", prefix, j)
			if b.Len()+len(line) > limit {
				break
			}
			b.WriteString(line)
		}
		return b.String()
	}
	var mu sync.Mutex
	bodies := map[string]string{}
	var document, rules strings.Builder
	document.WriteString("mode: rule\ndns:\n  enable: true\n  nameserver: [8.8.8.8]\nrule-providers:\n")
	names := []string{"set00", "set01", "set02", "set03", "set99"}
	for i, name := range names {
		limit := startTextSeedLimit - 64
		if name == "set99" {
			limit = 100 << 10
		}
		bodies["/"+name] = text(fmt.Sprintf("s%02d", i), limit)
		fmt.Fprintf(&document, "  %s:\n    type: http\n    behavior: domain\n    format: text\n    url: URL/%s\n    interval: 86400\n", name, name)
		fmt.Fprintf(&rules, "  - RULE-SET,%s,DIRECT\n", name)
	}
	document.WriteString("rules:\n" + rules.String() + "  - MATCH,DIRECT\n")
	var down atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		body := bodies[r.URL.Path]
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	finalized, err := FinalizeForIOS(strings.ReplaceAll(document.String(), "URL", server.URL), "{}")
	if err != nil {
		t.Fatal(err)
	}
	start := func() *BoxService {
		t.Helper()
		service, err := NewService(newRecordingPlatform())
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Start(finalized.Value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = service.Close() })
		return service
	}
	waitAll := func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			ok := true
			for _, name := range names {
				if liveRuleCountOf(name) <= 0 {
					ok = false
				}
			}
			if ok {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("not every set runs")
	}
	service := start()
	waitAll()
	before := liveRuleCountOf("set99")
	mu.Lock()
	bodies["/set99"] = text("grown", 3<<19)
	mu.Unlock()
	if answer := UpdateProviderJSON("rule", "set99", 15000); !strings.Contains(answer, `"result":"pendingApp"`) {
		t.Fatalf("the larger content does not wait for the App: %s", answer)
	}
	waitingFor := func() (string, string) {
		for _, entry := range readProviderCacheEntries(C.Path.HomeDir()) {
			if strings.HasSuffix(entry.URL, "/set99") {
				return entry.PendingSHA256, entry.PendingReason
			}
		}
		return "", ""
	}
	waiting, _ := waitingFor()
	_ = service.Close()
	if productGone {
		for requestKey, entry := range readProviderCacheEntries(C.Path.HomeDir()) {
			if !strings.HasSuffix(entry.URL, "/set99") {
				continue
			}
			for productKey, product := range entry.Products {
				if err := os.Remove(filepath.Join(providerCache.productDirectory(requestKey, productKey, product.Generation), product.Entry)); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	down.Store(true)
	if judgeRefuses {
		withBuildMemory(t, providerBuildFloorBytes)
		start()
		time.Sleep(time.Second)
		if n := liveRuleCountOf("set99"); n != 0 {
			t.Fatalf("set99 runs %d rules with the judge refusing its rebuild", n)
		}
		if sha, _ := waitingFor(); sha != waiting {
			t.Fatalf("a refused rebuild of the cache's content replaced the payload that waits (%s, was %s)", sha, waiting)
		}
		withBuildMemory(t, 1<<32)
	} else {
		start()
	}
	deadline := time.Now().Add(10 * time.Second)
	for liveRuleCountOf("set99") <= 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if liveRuleCountOf("set99") <= 0 {
		t.Fatalf("set99 ran %d rules before the restart and runs none after it", before)
	}
}
