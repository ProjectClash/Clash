package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/pause"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/exp/slices"
)

type GroupBase struct {
	*outbound.Base
	hidden            bool
	icon              string
	filterRegs        []*regexp2.Regexp
	excludeFilterRegs []*regexp2.Regexp
	excludeTypeArray  []string
	providers         []P.ProxyProvider
	failedTestMux     sync.Mutex
	failedMembers     failedMembers
	failedTimes       int
	failedTime        time.Time
	failedTesting     atomic.Bool
	testTimeout       int
	maxFailedTimes    int
	emptyFallback     C.Proxy

	// for GetProxies
	getProxiesMutex   sync.Mutex
	providerVersions  []uint32
	providerProxies   C.ProxyList
	membersGeneration uint64
	named             *namedMember
}

type GroupBaseOption struct {
	Name           string
	Type           C.AdapterType
	Hidden         bool
	Icon           string
	Filter         string
	ExcludeFilter  string
	ExcludeType    string
	TestTimeout    int
	MaxFailedTimes int
	EmptyFallback  C.Proxy
	Providers      []P.ProxyProvider
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var excludeTypeArray []string
	if opt.ExcludeType != "" {
		excludeTypeArray = strings.Split(opt.ExcludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if opt.ExcludeFilter != "" {
		for _, excludeFilter := range strings.Split(opt.ExcludeFilter, "`") {
			excludeFilterReg := utils.MustSharedRegexp2(excludeFilter)
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	if opt.Filter != "" {
		for _, filter := range strings.Split(opt.Filter, "`") {
			filterReg := utils.MustSharedRegexp2(filter)
			filterRegs = append(filterRegs, filterReg)
		}
	}

	gb := &GroupBase{
		Base:              outbound.NewBase(outbound.BaseOption{Name: opt.Name, Type: opt.Type}),
		hidden:            opt.Hidden,
		icon:              opt.Icon,
		filterRegs:        filterRegs,
		excludeFilterRegs: excludeFilterRegs,
		excludeTypeArray:  excludeTypeArray,
		providers:         opt.Providers,
		failedTesting:     atomic.NewBool(false),
		testTimeout:       opt.TestTimeout,
		maxFailedTimes:    opt.MaxFailedTimes,
		emptyFallback:     opt.EmptyFallback,
	}

	if gb.testTimeout == 0 {
		gb.testTimeout = 5000
	}
	if gb.maxFailedTimes == 0 {
		gb.maxFailedTimes = 5
	}

	return gb
}

func (gb *GroupBase) Hidden() bool {
	return gb.hidden
}

func (gb *GroupBase) Icon() string {
	return gb.icon
}

func (gb *GroupBase) EmptyFallback() C.Proxy {
	return gb.emptyFallback
}

func (gb *GroupBase) Touch() {
	for _, pd := range gb.providers {
		pd.Touch()
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	return C.ProxiesOf(gb.Members(touch))
}

func (gb *GroupBase) Members(touch bool) C.ProxyList {
	members, _ := gb.membersAndGeneration(touch)
	return members
}

func (gb *GroupBase) membersAndGeneration(touch bool) (C.ProxyList, uint64) {
	providerVersions := make([]uint32, len(gb.providers))
	for i, pd := range gb.providers {
		if touch { // touch first
			pd.Touch()
		}
		providerVersions[i] = pd.Version()
	}

	// thread safe
	gb.getProxiesMutex.Lock()
	defer gb.getProxiesMutex.Unlock()

	// return the cached proxies if version not changed
	if gb.providerProxies != nil && slices.Equal(providerVersions, gb.providerVersions) {
		return gb.providerProxies, gb.membersGeneration
	}

	var proxies C.ProxyList
	if len(gb.filterRegs) == 0 {
		lists := make([]C.ProxyList, 0, len(gb.providers))
		for _, pd := range gb.providers {
			lists = append(lists, pd.ProxyList())
		}
		proxies = C.ConcatProxyLists(lists...)
	} else {
		lists := make([]C.ProxyList, 0, len(gb.providers))
		for _, pd := range gb.providers {
			if pd.VehicleType() == P.Compatible { // compatible provider unneeded filter
				lists = append(lists, pd.ProxyList())
				continue
			}

			list := pd.ProxyList()
			var kept []uint32
			proxiesSet := map[string]struct{}{}
			for _, filterReg := range gb.filterRegs {
				for i := 0; i < list.Len(); i++ {
					name := list.At(i).Name()
					if mat, _ := filterReg.MatchString(name); mat {
						if _, ok := proxiesSet[name]; !ok {
							proxiesSet[name] = struct{}{}
							kept = append(kept, uint32(i))
						}
					}
				}
			}
			lists = append(lists, C.IndexedProxyList(list, kept))
		}
		proxies = C.ConcatProxyLists(lists...)
	}

	// Multiple filers means that proxies are sorted in the order in which the filers appear.
	// Although the filter has been performed once in the previous process,
	// when there are multiple providers, the array needs to be reordered as a whole.
	if len(gb.providers) > 1 && len(gb.filterRegs) > 1 {
		var kept []uint32
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range gb.filterRegs {
			for i := 0; i < proxies.Len(); i++ {
				name := proxies.At(i).Name()
				if mat, _ := filterReg.MatchString(name); mat {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						kept = append(kept, uint32(i))
					}
				}
			}
		}
		for i := 0; i < proxies.Len(); i++ { // add not matched proxies at the end
			name := proxies.At(i).Name()
			if _, ok := proxiesSet[name]; !ok {
				proxiesSet[name] = struct{}{}
				kept = append(kept, uint32(i))
			}
		}
		proxies = C.IndexedProxyList(proxies, kept)
	}

	if len(gb.excludeFilterRegs) > 0 {
		var kept []uint32
	LOOP1:
		for i := 0; i < proxies.Len(); i++ {
			name := proxies.At(i).Name()
			for _, excludeFilterReg := range gb.excludeFilterRegs {
				if mat, _ := excludeFilterReg.MatchString(name); mat {
					continue LOOP1
				}
			}
			kept = append(kept, uint32(i))
		}
		proxies = C.IndexedProxyList(proxies, kept)
	}

	if gb.excludeTypeArray != nil {
		var kept []uint32
	LOOP2:
		for i := 0; i < proxies.Len(); i++ {
			p := proxies.At(i)
			mType := p.Type().String()
			declared := ""
			if placeholder, ok := p.Adapter().(interface{ ClashDeclaredType() C.AdapterType }); ok {
				declared = placeholder.ClashDeclaredType().String()
			}
			for _, excludeType := range gb.excludeTypeArray {
				if strings.EqualFold(mType, excludeType) || (declared != "" && strings.EqualFold(declared, excludeType)) {
					continue LOOP2
				}
			}
			kept = append(kept, uint32(i))
		}
		proxies = C.IndexedProxyList(proxies, kept)
	}

	if proxies.Len() == 0 {
		gb.membersGeneration++
		gb.named = nil
		return C.ProxySlice{gb.EmptyFallback()}, gb.membersGeneration
	}

	// only cache when proxies not empty
	gb.providerVersions = providerVersions
	gb.providerProxies = proxies
	gb.membersGeneration++

	return proxies, gb.membersGeneration
}

func (gb *GroupBase) memberNamed(touch bool, name string) (C.Proxy, C.ProxyList, bool) {
	members, generation := gb.membersAndGeneration(touch)
	gb.getProxiesMutex.Lock()
	if found := gb.named; found != nil && found.generation == generation && found.name == name {
		gb.getProxiesMutex.Unlock()
		return found.proxy, members, found.proxy != nil
	}
	gb.getProxiesMutex.Unlock()
	var proxy C.Proxy
	for i := 0; i < members.Len(); i++ {
		if member := members.At(i); member.Name() == name {
			proxy = member
			break
		}
	}
	gb.getProxiesMutex.Lock()
	if gb.membersGeneration == generation {
		gb.named = &namedMember{generation: generation, name: name, proxy: proxy}
	}
	gb.getProxiesMutex.Unlock()
	return proxy, members, proxy != nil
}

type namedMember struct {
	generation uint64
	name       string
	proxy      C.Proxy
}

func (gb *GroupBase) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	var wg sync.WaitGroup
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.Members(false)
	running := make(chan struct{}, groupTestConcurrency)
	for i := 0; i < proxies.Len(); i++ {
		proxy := proxies.At(i)
		wg.Add(1)
		running <- struct{}{}
		go func() {
			defer func() { <-running }()
			var delay uint16
			var err error
			satisfied := true
			if outcomes, ok := proxy.(adapter.URLTestOutcomeProvider); ok {
				var outcome adapter.URLTestOutcome
				outcome, err = outcomes.URLTestOutcome(ctx, url, expectedStatus)
				delay, satisfied = outcome.Delay, outcome.Satisfied
			} else {
				delay, err = proxy.URLTest(ctx, url, expectedStatus)
			}
			if err == nil && satisfied {
				lock.Lock()
				mp[proxy.Name()] = delay
				lock.Unlock()
			}

			wg.Done()
		}()
	}
	wg.Wait()

	if len(mp) == 0 {
		return mp, fmt.Errorf("get delay: all proxies timeout")
	} else {
		return mp, nil
	}
}

func (gb *GroupBase) onDialFailed(proxy C.Proxy, err error, fn func()) {
	adapterType := proxy.Type()
	if adapterType == C.Direct || adapterType == C.Compatible || adapterType == C.Reject || adapterType == C.Pass || adapterType == C.RejectDrop {
		return
	}

	if errors.Is(err, C.ErrNotSupport) {
		return
	}

	gb.failedMembers.note(proxy.Name())
	go func() {
		if strings.Contains(err.Error(), "connection refused") {
			fn()
			return
		}

		gb.failedTestMux.Lock()
		defer gb.failedTestMux.Unlock()

		gb.failedTimes++
		if gb.failedTimes == 1 {
			log.Debugln("ProxyGroup: %s first failed", gb.Name())
			gb.failedTime = time.Now()
		} else {
			if time.Since(gb.failedTime) > time.Duration(gb.testTimeout)*time.Millisecond {
				gb.failedTimes = 0
				return
			}

			log.Debugln("ProxyGroup: %s failed count: %d", gb.Name(), gb.failedTimes)
			if gb.failedTimes >= gb.maxFailedTimes {
				if pause.IsDevicePaused() || pause.IsNetworkPaused() {
					log.Debugln("ProxyGroup: %s failed %d times while paused; no health check", gb.Name(), gb.failedTimes)
					return
				}
				log.Warnln("because %s failed multiple times, activate health check", gb.Name())
				fn()
			}
		}
	}()
}

func (gb *GroupBase) healthCheck() {
	if gb.failedTesting.Load() {
		return
	}

	gb.failedTesting.Store(true)
	failed := gb.failedMembers.take()
	wg := sync.WaitGroup{}
	for _, proxyProvider := range gb.providers {
		wg.Add(1)
		proxyProvider := proxyProvider
		go func() {
			defer wg.Done()
			healthCheckAfterDialFailures(proxyProvider, failed)
		}()
	}

	wg.Wait()
	gb.failedTesting.Store(false)
	gb.failedTimes = 0
}

func (gb *GroupBase) onDialSuccess() {
	if !gb.failedTesting.Load() {
		gb.failedTimes = 0
	}
}

const groupTestConcurrency = 64
