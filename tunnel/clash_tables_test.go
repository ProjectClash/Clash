package tunnel

import (
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/component/sniffer"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestTheTablesAreReadWhileTheySwap(t *testing.T) {
	previousProxies, previousProviders := loadProxies(), loadProviders()
	t.Cleanup(func() { UpdateProxies(previousProxies, previousProviders) })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for _, read := range []func(){
		func() { _ = len(Proxies()) },
		func() { _ = len(Providers()) },
		func() { _ = len(Tunnel.Proxies()) },
		func() { _, _ = lookupProxy("DIRECT") },
		func() { _ = len(Rules()) },
		func() { _ = len(RuleProviders()) },
		func() { _ = len(Listeners()) },
		func() { _ = len(SnapshotRuleProviders()) },
		func() { _ = Mode() },
		func() { _ = IsSniffing() },
		func() { _ = snifferDispatcher.Load().Enable() },
	} {
		wg.Add(1)
		go func(read func()) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					read()
				}
			}
		}(read)
	}
	previousSubRules := loadVersion().subRules
	previousRules, previousRuleProviders, previousListeners := loadRules(), loadRuleProviders(), loadListeners()
	previousMode, previousSniffer := Mode(), snifferDispatcher.Load()
	t.Cleanup(func() {
		UpdateRules(previousRules, previousSubRules, previousRuleProviders)
		UpdateListeners(previousListeners)
		SetMode(previousMode)
		UpdateSniffer(previousSniffer)
	})
	for i := 0; i < 2000; i++ {
		UpdateProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{})
		UpdateRules(nil, map[string][]C.Rule{}, map[string]P.RuleProvider{})
		UpdateProxiesAndRules(map[string]C.Proxy{}, map[string]P.ProxyProvider{}, nil, map[string][]C.Rule{}, map[string]P.RuleProvider{})
		UpdateListeners(map[string]C.InboundListener{})
		SetMode(Rule)
		UpdateSniffer(&sniffer.Dispatcher{})
	}
	close(stop)
	wg.Wait()
	if loadProxies() == nil || loadListeners() == nil {
		t.Error("a table upstream made at start is nil")
	}
}

func TestTheTablesReadAsUpstreamsInitialValuesBeforeTheFirstUpdate(t *testing.T) {
	configMux.Lock()
	previous := published.Load()
	published.Store(nil)
	configMux.Unlock()
	t.Cleanup(func() {
		configMux.Lock()
		published.Store(previous)
		configMux.Unlock()
	})
	if table := Proxies(); table == nil || len(table) != 0 {
		t.Errorf("proxies before the first update: %v", table)
	}
	if table := Listeners(); table == nil || len(table) != 0 {
		t.Errorf("listeners before the first update: %v", table)
	}
	if Providers() != nil || Rules() != nil || RuleProviders() != nil {
		t.Errorf("providers %v, rules %v, rule providers %v before the first update", Providers(), Rules(), RuleProviders())
	}
	if Mode() != Rule {
		t.Errorf("mode before the first update: %v", Mode())
	}
}
