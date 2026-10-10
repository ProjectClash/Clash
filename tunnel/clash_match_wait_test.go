package tunnel

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/process"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	RP "github.com/ProjectClash/Clash/rules/provider"
)

type hookResolver struct {
	resolver.Resolver
	hook func()
}

func (*hookResolver) Invalid() bool { return true }
func (r *hookResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	r.hook()
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

func init() { RP.SetTunnel(Tunnel) }

func withHookResolver(t *testing.T, hook func()) {
	t.Helper()
	oldResolver, oldIPv6, oldPolicy := resolver.DefaultResolver, resolver.DisableIPv6, resolver.CurrentIPQueryPolicy()
	t.Cleanup(func() {
		resolver.DefaultResolver = oldResolver
		resolver.DisableIPv6 = oldIPv6
		resolver.SetIPQueryPolicy(oldPolicy)
	})
	resolver.DefaultResolver = &hookResolver{hook: hook}
	resolver.DisableIPv6 = true
	resolver.SetIPQueryPolicy(resolver.IPQueryLegacy)
}

func within(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Errorf("%s did not finish", what)
	}
}

func reloadDuringWait(t *testing.T, reload func()) {
	reloaded := make(chan struct{})
	go func() {
		reload()
		close(reloaded)
	}()
	select {
	case <-reloaded:
	case <-time.After(5 * time.Second):
		t.Error("the reload waited for the rule's DNS answer: the match held configMux across it")
	}
}

func ipRules(t *testing.T, target string) []C.Rule {
	t.Helper()
	rule, err := R.ParseRule("IP-CIDR", "192.0.2.0/24", target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return []C.Rule{rule}
}

func waitTestProxies(names ...string) map[string]C.Proxy {
	proxies := map[string]C.Proxy{"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct}}
	for _, name := range names {
		proxies[name] = doorProxy{name: name, typ: C.Shadowsocks}
	}
	return proxies
}

func waitTestFlow() *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, Type: C.HTTP, Host: "example.test", DstPort: 443}
}

func TestAReloadLandsWhileARuleWaits(t *testing.T) {
	for name, reload := range map[string]func(rules []C.Rule){
		"UpdateRules":           func(rules []C.Rule) { UpdateRules(rules, nil, nil) },
		"UpdateProxiesAndRules": func(rules []C.Rule) { UpdateProxiesAndRules(waitTestProxies("before", "after"), nil, rules, nil, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			withDoorTestTunnel(t, "DIRECT")
			UpdateProxiesAndRules(waitTestProxies("before", "after"), nil, ipRules(t, "before"), nil, nil)
			var once sync.Once
			withHookResolver(t, func() { once.Do(func() { reloadDuringWait(t, func() { reload(ipRules(t, "after")) }) }) })
			if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "before" {
				t.Errorf("matched %v (%v); the flow began on the configuration that sends it to before", proxy, err)
			}
			if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "after" {
				t.Errorf("the next flow matched %v (%v); the reload sends it to after", proxy, err)
			}
		})
	}
}

type rematchTestAdapter struct {
	doorProxy
	subRule string
}

func (p rematchTestAdapter) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
	metadata.SpecialRules = p.subRule
	return nil, nil
}

type setTestProvider struct {
	P.RuleProvider
	matches bool
}

func (p setTestProvider) Match(*C.Metadata, C.RuleMatchHelper) bool { return p.matches }

func TestAFlowKeepsTheModeItsTablesWereTakenIn(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	previous := FindProcessMode()
	t.Cleanup(func() { SetFindProcessMode(previous) })
	SetFindProcessMode(process.FindProcessAlways)
	began := waitTestProxies("rule-proxy")
	began["GLOBAL"] = doorProxy{name: "old-global", typ: C.Shadowsocks}
	match, err := R.ParseRule("MATCH", "", "rule-proxy", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateProxiesAndRules(began, nil, []C.Rule{match}, nil, nil)
	SetMode(Rule)
	var once sync.Once
	process.SetConnectionOwnerResolver(func(string, netip.Addr, int, netip.Addr, int) (uint32, string, error) {
		once.Do(func() {
			reloadDuringWait(t, func() {
				reloaded := waitTestProxies("rule-proxy")
				reloaded["GLOBAL"] = doorProxy{name: "new-global", typ: C.Shadowsocks}
				UpdateProxiesAndRules(reloaded, nil, []C.Rule{match}, nil, nil)
				SetMode(Global)
			})
		})
		return 501, "/Applications/Test.app/Contents/MacOS/Test", nil
	})
	t.Cleanup(func() { process.SetConnectionOwnerResolver(nil) })
	if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "rule-proxy" {
		t.Errorf("matched %v (%v); the flow began in Rule mode", proxy, err)
	}
	if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "new-global" {
		t.Errorf("the next flow matched %v (%v); the reload switched to Global", proxy, err)
	}
}

func TestAFlowIsDecidedOnTheConfigurationItBeganWith(t *testing.T) {
	previousSubRules := loadVersion().subRules
	previousRuleProviders := loadRuleProviders()
	rule := func(kind, payload, target string) C.Rule {
		parsed, err := R.ParseRule(kind, payload, target, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	rematch := func(subRule string) C.Proxy {
		return rematchTestAdapter{doorProxy: doorProxy{name: "rematch", typ: C.Rematch}, subRule: subRule}
	}
	type configuration struct {
		proxies       map[string]C.Proxy
		rules         []C.Rule
		subRules      map[string][]C.Rule
		ruleProviders map[string]P.RuleProvider
	}
	for name, pair := range map[string][2]func() configuration{
		"a Rematch into sub-rules the reload renames": {
			func() configuration {
				proxies := waitTestProxies("first")
				proxies["rematch"] = rematch("sub")
				return configuration{proxies, []C.Rule{rule("MATCH", "", "rematch")}, map[string][]C.Rule{"sub": ipRules(t, "first")}, nil}
			},
			func() configuration {
				proxies := waitTestProxies("second")
				proxies["rematch"] = rematch("renamed")
				return configuration{proxies, []C.Rule{rule("MATCH", "", "rematch")}, map[string][]C.Rule{"renamed": ipRules(t, "second")}, nil}
			},
		},
		"a Rematch after the wait into sub-rules the reload changes": {
			func() configuration {
				proxies := waitTestProxies("first")
				proxies["rematch"] = rematch("sub")
				return configuration{proxies, ipRules(t, "rematch"), map[string][]C.Rule{"sub": {rule("MATCH", "", "first")}}, nil}
			},
			func() configuration {
				proxies := waitTestProxies("second")
				proxies["rematch"] = rematch("sub")
				return configuration{proxies, ipRules(t, "rematch"), map[string][]C.Rule{"sub": {rule("MATCH", "", "second")}}, nil}
			},
		},
		"a RULE-SET whose provider the reload replaces": {
			func() configuration {
				return configuration{waitTestProxies("first", "other"), []C.Rule{rule("IP-CIDR", "198.51.100.0/24", "other"), rule("RULE-SET", "set", "first"), rule("MATCH", "", "other")}, nil,
					map[string]P.RuleProvider{"set": setTestProvider{matches: true}}}
			},
			func() configuration {
				return configuration{waitTestProxies("first", "other"), []C.Rule{rule("IP-CIDR", "198.51.100.0/24", "other"), rule("RULE-SET", "set", "first"), rule("MATCH", "", "other")}, nil,
					map[string]P.RuleProvider{"set": setTestProvider{matches: false}}}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			withDoorTestTunnel(t, "DIRECT")
			t.Cleanup(func() { UpdateRules(Rules(), previousSubRules, previousRuleProviders) })
			began, reloaded := pair[0](), pair[1]()
			UpdateProxiesAndRules(began.proxies, nil, began.rules, began.subRules, began.ruleProviders)
			var once sync.Once
			withHookResolver(t, func() {
				once.Do(func() {
					reloadDuringWait(t, func() {
						UpdateProxiesAndRules(reloaded.proxies, nil, reloaded.rules, reloaded.subRules, reloaded.ruleProviders)
					})
				})
			})
			if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "first" {
				t.Errorf("matched %v (%v); the configuration the flow began with sends it to first", proxy, err)
			}
		})
	}
}

func TestCheckPassRuleReadsTheConfigurationTheFlowBeganWith(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	previousSubRules := loadVersion().subRules
	t.Cleanup(func() { UpdateRules(Rules(), previousSubRules, nil) })
	match, err := R.ParseRule("MATCH", "", "fallback", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sub := map[string][]C.Rule{"sub": {ipRules(t, "pass")[0], match}}
	subRule, err := R.ParseRule("SUB-RULE", "(NETWORK,TCP)", "sub", nil, sub)
	if err != nil {
		t.Fatal(err)
	}
	began := waitTestProxies("fallback")
	began["pass"] = doorProxy{name: "pass", typ: C.PassRule}
	UpdateProxiesAndRules(began, nil, []C.Rule{subRule}, sub, nil)
	var once sync.Once
	withHookResolver(t, func() {
		once.Do(func() {
			reloadDuringWait(t, func() { UpdateProxiesAndRules(waitTestProxies("pass", "fallback"), nil, []C.Rule{subRule}, sub, nil) })
		})
	})
	if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "fallback" {
		t.Errorf("matched %v (%v); in the configuration the flow began with, pass passes and fallback takes it", proxy, err)
	}
}

func TestADNSDialRoutedDuringARuleWaitDoesNotQueueBehindAReload(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	UpdateProxiesAndRules(waitTestProxies("relay"), nil, ipRules(t, "relay"), nil, nil)
	reloaded := make(chan struct{})
	var once sync.Once
	withHookResolver(t, func() {
		once.Do(func() {
			go func() {
				UpdateRules(ipRules(t, "relay"), nil, nil)
				close(reloaded)
			}()
			time.Sleep(50 * time.Millisecond)
			dialed := make(chan struct{})
			go func() {
				dnsDial := &C.Metadata{NetWork: C.UDP, Type: C.INNER, DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53}
				_, _, _ = resolveMetadata(dnsDial)
				close(dialed)
			}()
			select {
			case <-dialed:
			case <-time.After(5 * time.Second):
				t.Error("the resolver's routed dial queued behind the reload, which queued behind this match")
			}
		})
	})
	if proxy, _, err := resolveMetadata(waitTestFlow()); err != nil || proxy == nil || proxy.Name() != "relay" {
		t.Errorf("matched %v (%v)", proxy, err)
	}
	within(t, reloaded, "the reload")
}

func TestAReloadNeverPairsOneConfigurationsRulesWithAnothersProxies(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("a match overlaps a reload only on two threads")
	}
	withDoorTestTunnel(t, "DIRECT")
	configuration := func(group string) (map[string]C.Proxy, []C.Rule) {
		rule, err := R.ParseRule("MATCH", "", group, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return waitTestProxies(group), []C.Rule{rule}
	}
	proxiesA, rulesA := configuration("group-a")
	proxiesB, rulesB := configuration("group-b")
	UpdateProxiesAndRules(proxiesA, nil, rulesA, nil, nil)
	stop := make(chan struct{})
	var wg, running sync.WaitGroup
	var direct, matched atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		running.Add(1)
		go func() {
			defer wg.Done()
			running.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				proxy, _, _ := match(waitTestFlow(), C.RuleMatchHelper{}, loadVersion())
				matched.Add(1)
				if proxy != nil && proxy.Name() == "DIRECT" {
					direct.Add(1)
				}
			}
		}()
	}
	running.Wait()
	for matched.Load() < 100 {
		runtime.Gosched()
	}
	before := matched.Load()
	for i := 0; i < 20000; i++ {
		UpdateProxiesAndRules(proxiesB, nil, rulesB, nil, nil)
		UpdateProxiesAndRules(proxiesA, nil, rulesA, nil, nil)
	}
	during := matched.Load() - before
	close(stop)
	wg.Wait()
	if during == 0 {
		t.Error("no match ran while the reloads did")
	}
	if n := direct.Load(); n != 0 {
		t.Errorf("%d of %d matches met one configuration's rules with the other's proxies and went DIRECT", n, matched.Load())
	}
}

func TestLookupsDoNotQueueBehindAReload(t *testing.T) {
	configMux.RLock()
	reloaded := make(chan struct{})
	go func() {
		configMux.Lock()
		configMux.Unlock()
		close(reloaded)
	}()
	time.Sleep(50 * time.Millisecond)
	looked := make(chan struct{})
	go func() {
		_, _ = lookupProxy("DIRECT")
		_ = SnapshotRuleProviders()
		close(looked)
	}()
	select {
	case <-looked:
	case <-time.After(5 * time.Second):
		t.Error("a lookup queued behind the reload")
	}
	configMux.RUnlock()
	within(t, reloaded, "the reload")
	within(t, looked, "the lookup")
}
