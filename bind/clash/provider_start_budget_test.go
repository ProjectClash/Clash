package clash

import (
	"cmp"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

type stopgapStarts struct {
	t         *testing.T
	finalized string
	names     []string
	down      atomic.Bool
	mu        sync.Mutex
	bodies    map[string][]byte
}

func (s *stopgapStarts) serve(path, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies[path] = []byte(body)
}

func newStopgapStarts(t *testing.T, names []string, urls map[string]string, behaviors ...map[string]string) *stopgapStarts {
	t.Helper()
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
	starts := &stopgapStarts{t: t, names: names, bodies: map[string][]byte{}}
	bodies := starts.bodies
	var document strings.Builder
	var rules []string
	document.WriteString("mode: rule\ndns:\n  enable: true\n  nameserver: [8.8.8.8]\nrule-providers:\n")
	for i, name := range names {
		path := urls[name]
		if path == "" {
			path = name
		}
		if bodies["/"+path] == nil {
			var b strings.Builder
			for j := 0; ; j++ {
				line := fmt.Sprintf("s%02d-host-%06d.example.com\n", i, j)
				if b.Len()+len(line) > startTextSeedLimit-64 {
					break
				}
				b.WriteString(line)
			}
			bodies["/"+path] = []byte(b.String())
		}
		behavior := "domain"
		if len(behaviors) > 0 && behaviors[0][name] != "" {
			behavior = behaviors[0][name]
		}
		fmt.Fprintf(&document, "  %s:\n    type: http\n    behavior: %s\n    format: text\n    url: URL/%s\n    interval: 86400\n", name, behavior, path)
		rules = append([]string{fmt.Sprintf("  - RULE-SET,%s,DIRECT\n", name)}, rules...)
	}
	document.WriteString("rules:\n" + strings.Join(rules, "") + "  - MATCH,DIRECT\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if starts.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		starts.mu.Lock()
		body := bodies[r.URL.Path]
		starts.mu.Unlock()
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	finalized, err := FinalizeForIOS(strings.ReplaceAll(document.String(), "URL", server.URL), "{}")
	if err != nil {
		t.Fatal(err)
	}
	starts.finalized = finalized.Value
	return starts
}

func (s *stopgapStarts) start() *BoxService {
	s.t.Helper()
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		s.t.Fatal(err)
	}
	if err := service.Start(s.finalized); err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = service.Close() })
	return service
}

func (s *stopgapStarts) running() []string {
	var names []string
	for _, name := range s.names {
		if provider, ok := tunnel.RuleProviders()[name]; ok && provider.Count() > 0 {
			names = append(names, name)
		}
	}
	return names
}

func (s *stopgapStarts) waitForAll(what string) {
	s.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for len(s.running()) < len(s.names) {
		if time.Now().After(deadline) {
			s.t.Fatalf("%s: %v of %v run", what, s.running(), s.names)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *stopgapStarts) startHeld() (*BoxService, []string) {
	s.t.Helper()
	providerBuildGate.Lock()
	defer providerBuildGate.Unlock()
	service := s.start()
	return service, s.running()
}

func eightSets() []string {
	var names []string
	for i := 0; i < 8; i++ {
		names = append(names, fmt.Sprintf("set%02d", i))
	}
	return names
}

func headroomFor(n int) int64 {
	return startStopgapReserve + int64(n)*startTextSeedLimit*startStopgapCostFactor + 512<<10
}

func TestAStartServesStopgapsWithinItsHeadroomInRuleOrder(t *testing.T) {
	starts := newStopgapStarts(t, eightSets(), nil)
	service := starts.start()
	starts.waitForAll("the first start")
	_ = service.Close()

	starts.down.Store(true)
	withBuildMemory(t, headroomFor(4))
	_, served := starts.startHeld()
	if want := []string{"set04", "set05", "set06", "set07"}; !slices.Equal(served, want) {
		t.Fatalf("the start served %v, want the four the rules use first, %v", served, want)
	}
	starts.waitForAll("after the start, the refresher loading the rest from the cache")
}

func TestAReloadKeepsTheStopgapsThatRun(t *testing.T) {
	starts := newStopgapStarts(t, eightSets(), nil)
	service := starts.start()
	starts.waitForAll("the first start")
	withBuildMemory(t, headroomFor(1))
	providerBuildGate.Lock()
	err := service.Reload(starts.finalized)
	running := starts.running()
	providerBuildGate.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(running) != len(starts.names) {
		t.Fatalf("after a reload %v run, want all of %v", running, starts.names)
	}
}

func TestTwoNamesOfOneURLStartTogether(t *testing.T) {
	starts := newStopgapStarts(t, []string{"a1", "a2"}, map[string]string{"a1": "shared", "a2": "shared"})
	service := starts.start()
	starts.waitForAll("the first start")
	_ = service.Close()

	starts.down.Store(true)
	withBuildMemory(t, headroomFor(1))
	_, served := starts.startHeld()
	if len(served) == 1 {
		t.Fatalf("the start served %v of one request's two names", served)
	}
	starts.waitForAll("after the start")
}

func TestASetWaitingForHeadroomWithNothingRunningIsTriedAgainSoon(t *testing.T) {
	starts := newStopgapStarts(t, eightSets(), nil)
	service := starts.start()
	starts.waitForAll("the first start")
	_ = service.Close()

	starts.down.Store(true)
	withBuildMemory(t, 13<<20)
	starts.start()
	deadline := time.Now().Add(10 * time.Second)
	for {
		waiting := 0
		for _, entry := range readProviderCacheEntries(C.Path.HomeDir()) {
			if entry.Result == providerRefreshPendingApp && entry.PendingReason == providerRefreshPendingMemory {
				waiting++
			}
		}
		if waiting == len(starts.names) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d sets wait for headroom; %v run", waiting, len(starts.names), starts.running())
		}
		time.Sleep(20 * time.Millisecond)
	}
	withBuildMemory(t, 1<<32)
	starts.waitForAll("once the headroom is back")
	deadline = time.Now().Add(5 * time.Second)
	for {
		settled := 0
		for _, entry := range readProviderCacheEntries(C.Path.HomeDir()) {
			if entry.Result == providerRefreshUpdated && entry.PendingSHA256 == "" {
				settled++
			}
		}
		if settled == len(starts.names) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d records say the set runs with nothing waiting", settled, len(starts.names))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTwoFormsOfOneURLStartTogether(t *testing.T) {
	setup := testOptions(t)
	setup.RuntimeProfile = RuntimeProfileIOSPacketTunnel
	if err := Setup(setup); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(setup.WorkingPath)
	pointProviderCacheAtHome()
	plan := &providerRefreshPlan{budget: startBudget{limited: true, left: startTextSeedLimit * startStopgapCostFactor}}
	var targets []*providerRefreshTarget
	for _, form := range []struct{ name, productKey string }{{"b1", "rule/domain/text"}, {"b2", "rule/classical/text"}} {
		product := &providerCacheProduct{Variant: "text", Entry: "stopgap", Stopgap: true, Generation: "g", Format: "text", Behavior: "domain"}
		directory := providerCache.productDirectory("one request", form.productKey, product.Generation)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, product.Entry), make([]byte, startTextSeedLimit-1), 0o600); err != nil {
			t.Fatal(err)
		}
		target := &providerRefreshTarget{kind: "rule", name: form.name, requestKey: "one request", productKey: form.productKey, definition: map[string]any{}}
		if !plan.offerStopgap(target, product, func() string { return t.TempDir() }) {
			t.Fatalf("%s's stopgap was not offered", form.name)
		}
		targets = append(targets, target)
	}
	plan.decideStartStopgaps()
	if (targets[0].product == nil) != (targets[1].product == nil) {
		t.Fatalf("the start served %v and %v of one request's two forms", targets[0].product != nil, targets[1].product != nil)
	}
}

func TestTheStartRanksASetWhereTheConfigurationFirstUsesIt(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
dns:
  fake-ip-filter: ['rule-set:lan']
  proxy-server-nameserver-policy:
    'rule-set:nodes': 8.8.8.8
sniffer:
  skip-domain: ['rule-set:sniffless']
tun:
  route-exclude-address-set: [routes]
rules:
  - RULE-SET,first,DIRECT
  - AND,((RULE-SET,second),(NETWORK,UDP)),DIRECT
  - SUB-RULE,(NETWORK,TCP),inner
  - MATCH,DIRECT
sub-rules:
  inner:
    - RULE-SET,nested,DIRECT
rule-providers:
  lan: {type: http, behavior: domain, url: 'http://x/a'}
  nodes: {type: http, behavior: domain, url: 'http://x/b'}
  sniffless: {type: http, behavior: domain, url: 'http://x/c'}
  routes: {type: http, behavior: ipcidr, url: 'http://x/d'}
  first: {type: http, behavior: domain, url: 'http://x/e'}
  second: {type: http, behavior: domain, url: 'http://x/f'}
  nested: {type: http, behavior: domain, url: 'http://x/g'}
  unused: {type: http, behavior: domain, url: 'http://x/h'}
`))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"lan", "nodes", "sniffless", "routes", "first", "second", "nested", "unused"}
	ranks := startRanks(raw)
	order := slices.Clone(names)
	slices.SortStableFunc(order, func(a, b string) int {
		ra, okA := ranks[a]
		rb, okB := ranks[b]
		if !okA {
			ra = math.MaxInt
		}
		if !okB {
			rb = math.MaxInt
		}
		return cmp.Compare(ra, rb)
	})
	if want := []string{"lan", "nodes", "sniffless", "routes", "first", "second", "nested", "unused"}; !slices.Equal(order, want) {
		t.Fatalf("the start would serve in the order %v (ranks %v), want %v", order, ranks, want)
	}
	if ranks["nested"] != 2 {
		t.Fatalf("a sub-rule's set ranks %d, want 2, the rule that names the sub-rule", ranks["nested"])
	}
	if _, ranked := ranks["unused"]; ranked {
		t.Fatalf("a set nothing uses has a rank: %d", ranks["unused"])
	}
}

func TestANewerPayloadWaitingForHeadroomIsTriedBeforeTheOlderContent(t *testing.T) {
	starts := newStopgapStarts(t, []string{"y1"}, nil)
	service := starts.start()
	starts.waitForAll("the first start, the older content near the limit")
	starts.serve("/y1", "a.example\nb.example\nc.example\n")
	if answer := UpdateProviderJSON("rule", "y1", 15000); !strings.Contains(answer, `"result":"pendingApp"`) {
		t.Fatalf("the newer content does not wait beside what runs: %s", answer)
	}
	_ = service.Close()

	starts.down.Store(true)
	withBuildMemory(t, providerBuildFloorBytes)
	starts.start()
	deadline := time.Now().Add(10 * time.Second)
	for {
		entries := readProviderCacheEntries(C.Path.HomeDir())
		waiting := false
		for _, entry := range entries {
			waiting = waiting || entry.PendingReason == providerRefreshPendingMemory && entry.PendingSHA256 != entry.SourceSHA256
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the newer content does not wait for headroom: %+v", entries)
		}
		time.Sleep(20 * time.Millisecond)
	}
	withBuildMemory(t, providerBuildFloorBytes+1<<20)
	deadline = time.Now().Add(10 * time.Second)
	for liveRuleCountOf("y1") != 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the set runs %d rules; the newer content that fits was never tried", liveRuleCountOf("y1"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestARetryThatTriesBothContentsCountsOneFailure(t *testing.T) {
	starts := newStopgapStarts(t, []string{"y1"}, nil)
	service := starts.start()
	starts.waitForAll("the first start, the older content near the limit")
	starts.serve("/y1", "a.example\nb.example\nc.example\n")
	if answer := UpdateProviderJSON("rule", "y1", 15000); !strings.Contains(answer, `"result":"pendingApp"`) {
		t.Fatalf("the newer content does not wait beside what runs: %s", answer)
	}
	_ = service.Close()

	starts.down.Store(true)
	withBuildMemory(t, providerBuildFloorBytes)
	providerRefreshFirstLoadMinimum = 2 * time.Second
	starts.start()
	nextDue := func() int64 {
		for _, entry := range readProviderCacheEntries(C.Path.HomeDir()) {
			if entry.PendingReason == providerRefreshPendingMemory {
				return entry.NextDueAt
			}
		}
		return 0
	}
	deadline := time.Now().Add(10 * time.Second)
	first := nextDue()
	for first == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the set never waited for headroom")
		}
		time.Sleep(20 * time.Millisecond)
		first = nextDue()
	}
	second := first
	for second == first {
		if time.Now().After(deadline) {
			t.Fatal("the set was not tried again")
		}
		time.Sleep(20 * time.Millisecond)
		second = nextDue()
	}
	if wait := second - time.Now().Unix(); wait > 5 {
		t.Fatalf("the second try waits %d s; one failure a try is four", wait)
	}
}
