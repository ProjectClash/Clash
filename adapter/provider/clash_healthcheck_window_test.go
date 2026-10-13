package provider

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/singledo"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
)

const windowTestURL = "http://127.0.0.1:1/never"

type probeLog struct {
	mu    sync.Mutex
	names []string
	byURL map[string][]string
}

func (l *probeLog) add(name, url string) {
	l.mu.Lock()
	l.names = append(l.names, name)
	if l.byURL == nil {
		l.byURL = map[string][]string{}
	}
	l.byURL[url] = append(l.byURL[url], name)
	l.mu.Unlock()
}

func (l *probeLog) takeURL(url string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	names := l.byURL[url]
	delete(l.byURL, url)
	return names
}

func (l *probeLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	names := l.names
	l.names = nil
	return names
}

type windowNode struct {
	*adapter.Proxy
	log  *probeLog
	gate chan struct{}

	mu      sync.Mutex
	records map[string]windowRecord
}

type windowRecord struct {
	delay uint16
	alive bool
}

func (w *windowNode) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	if w.gate != nil {
		<-w.gate
	}
	w.log.add(w.Name(), url)
	return 0, errors.New("not dialed")
}

func (w *windowNode) LastURLTestRecord(url string) (C.DelayHistory, bool, string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	record, ok := w.records[url]
	if !ok {
		return C.DelayHistory{}, false, "", false
	}
	return C.DelayHistory{Time: time.Now().Add(-time.Hour), Delay: record.delay}, record.alive, "*", true
}

func (w *windowNode) plant(url string, delay uint16, alive bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.records == nil {
		w.records = map[string]windowRecord{}
	}
	w.records[url] = windowRecord{delay: delay, alive: alive}
}

func windowNodes(n int, log *probeLog) []*windowNode {
	nodes := make([]*windowNode, n)
	for i := range nodes {
		direct := outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("n%06d", i)})
		nodes[i] = &windowNode{Proxy: adapter.NewProxy(direct), log: log}
	}
	return nodes
}

func windowProxies(nodes []*windowNode) []C.Proxy {
	proxies := make([]C.Proxy, len(nodes))
	for i, node := range nodes {
		proxies[i] = node
	}
	return proxies
}

func anotherScheduledRound(hc *HealthCheck) {
	hc.round(singledo.NewSingle[struct{}](0), time.Now(), true)
}

func nameSet(names []string) map[string]int {
	set := map[string]int{}
	for _, name := range names {
		set[name]++
	}
	return set
}

func TestABackgroundRoundOfALargeGroupMeasuresAWindow(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)

	healthCheck.checkScheduled()

	probed := nameSet(log.take())
	if len(probed) != roundWindow {
		t.Fatalf("a scheduled round of %d members probed %d, want the window's %d", len(nodes), len(probed), roundWindow)
	}
	for name, times := range probed {
		if times != 1 {
			t.Fatalf("%s was probed %d times in one round", name, times)
		}
	}
}

func TestTheWindowMovesOnRoundAfterRound(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)

	healthCheck.checkScheduled()
	first := nameSet(log.take())
	anotherScheduledRound(healthCheck)
	second := nameSet(log.take())
	for name := range second {
		if first[name] != 0 {
			t.Fatalf("%s was measured by two consecutive rounds of %d members; the second should begin where the first ended", name, len(nodes))
		}
	}
	anotherScheduledRound(healthCheck)
	third := nameSet(log.take())
	for _, node := range nodes {
		name := node.Name()
		if first[name]+second[name]+third[name] == 0 {
			t.Fatalf("%s was not measured in three rounds of a %d-member window over %d members", name, roundWindow, len(nodes))
		}
	}
	if len(third) != roundWindow {
		t.Fatalf("the third round measured %d, want the window's %d: the last members, then the first again", len(third), roundWindow)
	}
	if third[nodes[0].Name()] == 0 {
		t.Fatal("the window did not wrap round to the first member")
	}
}

func TestTheWindowTakesTheChosenAndTheFastestKnownFirst(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*3, log)
	const extraURL = "http://127.0.0.1:1/extra"
	fastest := map[string]bool{}
	for k := 0; k <= roundBestKnown; k++ {
		node := nodes[len(nodes)-1-k]
		node.plant(windowTestURL, uint16(100+roundBestKnown-k), true)
		if k > 0 {
			fastest[node.Name()] = true
		}
	}
	slowest := nodes[len(nodes)-1]
	dead := nodes[len(nodes)-200]
	dead.plant(windowTestURL, 1, false)
	extraFastest := nodes[len(nodes)-300]
	extraFastest.plant(extraURL, 50, true)
	chosen := nodes[len(nodes)-400]
	withHealthCheckFirst(t, chosen.Name())

	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	healthCheck.registerHealthCheckTask(extraURL, nil, "", 300)
	windows := healthCheck.windows(chosenFirst(healthCheck.snapshotProxies()))
	window := windows(windowTestURL)
	if extra := windows(extraURL); extra.At(0).Name() != chosen.Name() || extra.At(1).Name() != extraFastest.Name() {
		t.Fatalf("the extra URL's window begins %s, %s; want the chosen, then its own fastest known", extra.At(0).Name(), extra.At(1).Name())
	}

	if window.Len() != roundWindow {
		t.Fatalf("the window holds %d members, want %d", window.Len(), roundWindow)
	}
	if got := window.At(0).Name(); got != chosen.Name() {
		t.Fatalf("the window begins with %s, want the chosen %s", got, chosen.Name())
	}
	head := map[string]bool{}
	for i := 1; i <= roundBestKnown; i++ {
		head[window.At(i).Name()] = true
	}
	for name := range fastest {
		if !head[name] {
			t.Fatalf("%s, among the %d fastest known, is not measured right after the chosen", name, roundBestKnown)
		}
	}
	members := map[string]bool{}
	for i := 0; i < window.Len(); i++ {
		members[window.At(i).Name()] = true
	}
	if members[slowest.Name()] {
		t.Fatalf("the window took the %dth fastest known; it is the cursor's to reach", roundBestKnown+1)
	}
	if members[dead.Name()] {
		t.Fatal("the window took a member whose newest record is dead as one of the fastest known")
	}
	if !members[nodes[0].Name()] {
		t.Fatal("the rest of the window does not begin at the first member")
	}
}

func TestAProviderHealthCheckStillMeasuresEveryMember(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	provider, err := NewCompatibleProvider("p", windowProxies(nodes), healthCheck)
	if err != nil {
		t.Fatal(err)
	}

	provider.HealthCheck()

	if probed := nameSet(log.take()); len(probed) != len(nodes) {
		t.Fatalf("a provider health check of %d members probed %d", len(nodes), len(probed))
	}
}

func TestARoundAfterDialFailuresOfALargeGroupMeasuresAWindow(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	provider, err := NewCompatibleProvider("p", windowProxies(nodes), healthCheck)
	if err != nil {
		t.Fatal(err)
	}

	provider.HealthCheckAfterDialFailures()

	if probed := nameSet(log.take()); len(probed) != roundWindow {
		t.Fatalf("a round after dial failures of %d members probed %d, want the window's %d", len(nodes), len(probed), roundWindow)
	}
}

func TestARoundAfterANetworkChangeOfALargeGroupMeasuresAWindow(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	provider, err := NewCompatibleProvider("p", windowProxies(nodes), healthCheck)
	if err != nil {
		t.Fatal(err)
	}

	provider.HealthCheckAfterNetworkChange()
	if !waitFor(func() bool { return !healthCheck.networkRounds.isRunning() }) {
		t.Fatal("the round after the network change did not finish")
	}

	if probed := nameSet(log.take()); len(probed) != roundWindow {
		t.Fatalf("a round after a network change of %d members probed %d, want the window's %d", len(nodes), len(probed), roundWindow)
	}
}

func TestAGroupNoLargerThanTheWindowIsMeasuredWhole(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)

	healthCheck.checkScheduled()
	if probed := nameSet(log.take()); len(probed) != roundWindow {
		t.Fatalf("a scheduled round of %d members probed %d, want all", roundWindow, len(probed))
	}
	anotherScheduledRound(healthCheck)
	if probed := nameSet(log.take()); len(probed) != roundWindow {
		t.Fatalf("the next scheduled round of %d members probed %d, want all", roundWindow, len(probed))
	}
}

func TestTheWindowSurvivesAShorterList(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*3, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	healthCheck.checkScheduled()
	anotherScheduledRound(healthCheck)
	log.take()

	healthCheck.setProxies(windowProxies(nodes[:roundWindow*3/2]))
	anotherScheduledRound(healthCheck)

	probed := nameSet(log.take())
	if len(probed) != roundWindow {
		t.Fatalf("a round after the list shrank probed %d, want the window's %d", len(probed), roundWindow)
	}
	for name := range probed {
		var i int
		if _, err := fmt.Sscanf(name, "n%06d", &i); err != nil || i >= roundWindow*3/2 {
			t.Fatalf("the round probed %s, not a member of the list it was given", name)
		}
	}
}

func TestTheRoundAfterAProviderLoadsMeasuresAWindow(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(nil, windowTestURL, 1000, 300, false, nil)
	provider, err := NewCompatibleProvider("p", windowProxies(nodes[:1]), healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	provider.setProxies(windowProxies(nodes))
	if !waitFor(func() bool { log.mu.Lock(); defer log.mu.Unlock(); return len(log.names) >= roundWindow }) {
		t.Fatal("no round after the nodes loaded")
	}
	time.Sleep(100 * time.Millisecond)
	if probed := nameSet(log.take()); len(probed) != roundWindow {
		t.Fatalf("the round after %d nodes loaded probed %d, want the window's %d", len(nodes), len(probed), roundWindow)
	}
}

func TestTheWindowsPriorityLeavesRoomForTheRest(t *testing.T) {
	nodes := windowNodes(roundWindow*4, &probeLog{})
	var names []string
	for i := 0; i < roundWindow*7/10; i++ {
		names = append(names, nodes[len(nodes)-1-i].Name())
	}
	withHealthCheckFirst(t, names...)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	for round := 0; round < 2; round++ {
		window := healthCheck.windows(chosenFirst(healthCheck.snapshotProxies()))(windowTestURL)
		chosen := 0
		for i := 0; i < window.Len(); i++ {
			var index int
			fmt.Sscanf(window.At(i).Name(), "n%06d", &index)
			if index >= len(nodes)-len(names) {
				chosen++
			}
		}
		if window.Len() != roundWindow || chosen != roundPriority {
			t.Fatalf("round %d: a window of %d with %d chosen, want %d with %d", round, window.Len(), chosen, roundWindow, roundPriority)
		}
	}
	healthCheck.mu.Lock()
	moved := healthCheck.windowNext[windowTestURL]
	healthCheck.mu.Unlock()
	if moved != 2*(roundWindow-roundPriority) {
		t.Fatalf("the cursor moved %d in two windows, want %d", moved, 2*(roundWindow-roundPriority))
	}
}

func TestAFilteredGroupOfALargeProviderIsMeasuredEveryRound(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5, log)
	const groupURL = "http://127.0.0.1:1/hk"
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	healthCheck.registerHealthCheckTask(groupURL, nil, `^n0049[5-9]\d$`, 300)
	healthCheck.checkScheduled()
	for round := 0; round < 4; round++ {
		if round > 0 {
			anotherScheduledRound(healthCheck)
		}
		if probed := nameSet(log.takeURL(groupURL)); len(probed) != 50 {
			t.Fatalf("round %d probed %d of the group's 50 under its URL", round, len(probed))
		}
		if probed := nameSet(log.takeURL(windowTestURL)); len(probed) != roundWindow {
			t.Fatalf("round %d probed %d under the provider's URL, want the window's %d", round, len(probed), roundWindow)
		}
	}
}

func TestTheRoundAfterDialFailuresMeasuresTheFailedMembers(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	provider, err := NewCompatibleProvider("p", windowProxies(nodes), healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	failed := nodes[len(nodes)-7].Name()
	provider.HealthCheckAfterDialFailures(failed)
	probed := log.take()
	if len(nameSet(probed)) != roundWindow || nameSet(probed)[failed] != 1 {
		t.Fatalf("the round after %s failed probed %d members, it %d times", failed, len(nameSet(probed)), nameSet(probed)[failed])
	}
}

func TestWindowsTakenAtOnceDoNotRepeat(t *testing.T) {
	nodes := windowNodes(roundWindow*8, &probeLog{})
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	var wg sync.WaitGroup
	windows := make([]C.ProxyList, 8)
	for i := range windows {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			windows[i] = healthCheck.windows(healthCheck.snapshotProxies())(windowTestURL)
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, w := range windows {
		for i := 0; i < w.Len(); i++ {
			if seen[w.At(i).Name()] {
				t.Fatalf("%s is in two windows taken at once", w.At(i).Name())
			}
			seen[w.At(i).Name()] = true
		}
	}
}

func TestTheFastestKnownOfAURLAreTheOnesItsFilterMeasures(t *testing.T) {
	nodes := windowNodes(roundWindow*3, &probeLog{})
	const jpURL = "http://127.0.0.1:1/jp"
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	healthCheck.registerHealthCheckTask(jpURL, nil, "^n0029", 300)
	for k := 0; k < roundBestKnown; k++ {
		nodes[1000+k].plant(jpURL, 5, true)
	}
	jp := nodes[2950]
	jp.plant(jpURL, 50, true)
	window := healthCheck.windows(chosenFirst(healthCheck.snapshotProxies()))(jpURL)
	for i := 0; i < window.Len(); i++ {
		var index int
		fmt.Sscanf(window.At(i).Name(), "n%06d", &index)
		if index < 2900 || index > 2999 {
			t.Fatalf("%s, which the filter does not measure, is in its URL's window", window.At(i).Name())
		}
	}
	for i := 0; i < roundBestKnown && i < window.Len(); i++ {
		if window.At(i).Name() == jp.Name() {
			return
		}
	}
	t.Fatalf("%s, the fastest the filter measures, is not among the window's first", jp.Name())
}

func TestMembersThatFailWhileARoundRunsAreMeasuredByTheNext(t *testing.T) {
	log := &probeLog{}
	nodes := windowNodes(roundWindow*5/2, log)
	gate := make(chan struct{})
	nodes[0].gate = gate
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	provider, err := NewCompatibleProvider("p", windowProxies(nodes), healthCheck)
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(chan struct{})
	go func() {
		defer close(loaded)
		healthCheck.checkLoaded()
	}()
	time.Sleep(50 * time.Millisecond)
	failed := nodes[len(nodes)-3].Name()
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		provider.HealthCheckAfterDialFailures(failed)
	}()
	time.Sleep(50 * time.Millisecond)
	close(gate)
	<-loaded
	<-joined
	if first := nameSet(log.take()); first[failed] != 0 {
		t.Skip("the failed member's round began on its own; nothing joined")
	}
	anotherScheduledRound(healthCheck)
	if next := nameSet(log.take()); next[failed] != 1 {
		t.Fatalf("%s, which failed while a round ran, was not measured by the next round", failed)
	}
}

func TestTheFailedComeBeforeTheChosen(t *testing.T) {
	nodes := windowNodes(roundWindow*4, &probeLog{})
	var names []string
	for i := 0; i < roundWindow*6/10; i++ {
		names = append(names, nodes[1000+i].Name())
	}
	withHealthCheckFirst(t, names...)
	healthCheck := NewHealthCheck(windowProxies(nodes), windowTestURL, 1000, 300, false, nil)
	failed := nodes[3900].Name()
	window := healthCheck.windows(chosenFirst(healthCheck.snapshotProxies(), failed))(windowTestURL)
	if window.At(0).Name() != failed {
		t.Fatalf("the window begins with %s, want the failed %s", window.At(0).Name(), failed)
	}
}
