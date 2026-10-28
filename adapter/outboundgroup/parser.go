package outboundgroup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/common/structure"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupported type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	Name                string   `group:"name"`
	Type                string   `group:"type"`
	Proxies             []string `group:"proxies,omitempty"`
	Use                 []string `group:"use,omitempty"`
	URL                 string   `group:"url,omitempty"`
	Interval            int      `group:"interval,omitempty"`
	TestTimeout         int      `group:"timeout,omitempty"`
	MaxFailedTimes      int      `group:"max-failed-times,omitempty"`
	EmptyFallback       string   `group:"empty-fallback,omitempty"`
	Lazy                bool     `group:"lazy,omitempty"`
	DisableUDP          bool     `group:"disable-udp,omitempty"`
	Filter              string   `group:"filter,omitempty"`
	ExcludeFilter       string   `group:"exclude-filter,omitempty"`
	ExcludeType         string   `group:"exclude-type,omitempty"`
	ExpectedStatus      string   `group:"expected-status,omitempty"`
	IncludeAll          bool     `group:"include-all,omitempty"`
	IncludeAllProxies   bool     `group:"include-all-proxies,omitempty"`
	IncludeAllProviders bool     `group:"include-all-providers,omitempty"`
	Hidden              bool     `group:"hidden,omitempty"`
	Icon                string   `group:"icon,omitempty"`
}

type GroupNodes struct {
	Lookup func(name string) (C.Proxy, bool)
	All    C.ProxyList
	Library C.ProxyList
	Group func(name string) ([]uint32, bool)
	Internal []int
}

const clashInternalField = "x-clash-internal"

func IsClashInternalProxy(mapping map[string]any) bool {
	switch v := mapping[clashInternalField].(type) {
	case bool:
		return v
	case string:
		internal, err := strconv.ParseBool(v)
		return err == nil && internal
	}
	return false
}

const clashMemberGroupField = "x-clash-member-group"

const clashMembersField = "x-clash-members"

func clashMembers(config map[string]any, lookup func(string) (C.Proxy, bool), library C.ProxyList) (C.ProxyList, bool, error) {
	raw, present := config[clashMembersField]
	if !present {
		return nil, false, nil
	}
	entries, isList := raw.([]any)
	if !isList {
		return nil, true, fmt.Errorf("%s: not a list", clashMembersField)
	}
	var lists []C.ProxyList
	var names []string
	flush := func() error {
		if len(names) == 0 {
			return nil
		}
		named, err := getProxiesFrom(lookup, names)
		if err != nil {
			return err
		}
		lists, names = append(lists, C.ProxySlice(named)), nil
		return nil
	}
	for _, entry := range entries {
		switch entry := entry.(type) {
		case string:
			names = append(names, entry)
		case map[string]any:
			from, fromOK := entry["from"].(int)
			to, toOK := entry["to"].(int)
			if !fromOK || !toOK || library == nil || from < 0 || to <= from || to > library.Len() {
				return nil, true, fmt.Errorf("%s: a run out of the library", clashMembersField)
			}
			if err := flush(); err != nil {
				return nil, true, err
			}
			lists = append(lists, C.SubProxyList(library, from, to))
		default:
			return nil, true, fmt.Errorf("%s: an entry that is neither a name nor a run", clashMembersField)
		}
	}
	if err := flush(); err != nil {
		return nil, true, err
	}
	return C.ConcatProxyLists(lists...), true, nil
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]P.ProxyProvider, AllProxies []string, AllProviders []string, nodes ...GroupNodes) (ProxyGroup, error) {
	lookup := func(name string) (C.Proxy, bool) {
		if p, ok := proxyMap[name]; ok {
			return p, true
		}
		for _, n := range nodes {
			if p, ok := n.Lookup(name); ok {
				return p, true
			}
		}
		return nil, false
	}
	var allNodes, libraryNodes C.ProxyList
	var computedGroup func(string) ([]uint32, bool)
	var internalNodes []int
	for _, n := range nodes {
		allNodes, libraryNodes, computedGroup, internalNodes = n.All, n.Library, n.Group, n.Internal
	}
	var libraryMembers C.ProxyList = C.ProxySlice(nil)
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := GroupCommonOption{
		Lazy: true,
	}
	if err := decoder.Decode(config, &groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	if _, ok := config["routing-mark"]; ok {
		log.Errorln("The group [%s] with routing-mark configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if _, ok := config["interface-name"]; ok {
		log.Errorln("The group [%s] with interface-name configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if _, ok := config["dialer-proxy"]; ok {
		log.Errorln("The group [%s] with dialer-proxy configuration is not allowed, please set it directly on the proxy instead", groupOption.Name)
	}

	groupName := groupOption.Name

	members, compacted, err := clashMembers(config, lookup, libraryNodes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", groupName, err)
	}
	if !compacted {
		members = C.ProxySlice(nil)
	}
	if name, ok := config[clashMemberGroupField].(string); ok {
		indexes, found := []uint32(nil), false
		if computedGroup != nil && allNodes != nil {
			indexes, found = computedGroup(name)
		}
		if !found {
			return nil, fmt.Errorf("%s: %s names no members the library holds", groupName, clashMemberGroupField)
		}
		for _, at := range indexes {
			if int(at) >= allNodes.Len() {
				return nil, fmt.Errorf("%s: %s: a member outside the nodes", groupName, clashMemberGroupField)
			}
		}
		libraryMembers = C.IndexedProxyList(allNodes, indexes)
	}

	if groupOption.EmptyFallback == "" {
		groupOption.EmptyFallback = "COMPATIBLE"
	}
	emptyFallback, ok := lookup(groupOption.EmptyFallback)
	if !ok {
		return nil, fmt.Errorf("%s: empty fallback proxy '%s' not found", groupName, groupOption.EmptyFallback)
	}
	if _, ok := emptyFallback.Adapter().(ProxyGroup); ok { // strictly forbidden to fill in a proxy group for empty-fallback
		return nil, fmt.Errorf("%s: empty fallback proxy '%s' not found", groupName, groupOption.EmptyFallback)
	}

	providers := []P.ProxyProvider{}

	if groupOption.IncludeAll {
		groupOption.IncludeAllProviders = true
		groupOption.IncludeAllProxies = true
	}

	if groupOption.IncludeAllProviders {
		groupOption.Use = AllProviders
	}
	if groupOption.IncludeAllProxies && allNodes != nil {
		if groupOption.Filter != "" {
			var filterRegs []*regexp2.Regexp
			for _, filter := range strings.Split(groupOption.Filter, "`") {
				filterRegs = append(filterRegs, utils.MustSharedRegexp2(filter))
			}
			var kept []uint32
			skip := internalNodes
			for i := 0; i < allNodes.Len(); i++ {
				if len(skip) != 0 && skip[0] == i {
					skip = skip[1:]
					continue
				}
				name := allNodes.At(i).Name()
				for _, filterReg := range filterRegs {
					if mat, _ := filterReg.MatchString(name); mat {
						kept = append(kept, uint32(i))
					}
				}
			}
			libraryMembers = C.IndexedProxyList(allNodes, kept)
		} else {
			libraryMembers = C.ProxyListWithout(allNodes, internalNodes)
		}
		if len(groupOption.Proxies) == 0 && members.Len() == 0 && libraryMembers.Len() == 0 && len(groupOption.Use) == 0 {
			groupOption.Proxies = []string{groupOption.EmptyFallback}
		}
	} else if groupOption.IncludeAllProxies {
		if groupOption.Filter != "" {
			var filterRegs []*regexp2.Regexp
			for _, filter := range strings.Split(groupOption.Filter, "`") {
				filterReg := utils.MustSharedRegexp2(filter)
				filterRegs = append(filterRegs, filterReg)
			}
			for _, p := range AllProxies {
				for _, filterReg := range filterRegs {
					if mat, _ := filterReg.MatchString(p); mat {
						groupOption.Proxies = append(groupOption.Proxies, p)
					}
				}
			}
		} else {
			groupOption.Proxies = append(groupOption.Proxies, AllProxies...)
		}
		if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
			groupOption.Proxies = []string{groupOption.EmptyFallback}
		}
	}

	if len(groupOption.Proxies) == 0 && members.Len() == 0 && libraryMembers.Len() == 0 && len(groupOption.Use) == 0 {
		return nil, fmt.Errorf("%s: %w", groupName, errMissProxy)
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](groupOption.ExpectedStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", groupName, err)
	}

	status := strings.TrimSpace(groupOption.ExpectedStatus)
	if status == "" {
		status = "*"
	}
	groupOption.ExpectedStatus = status

	if len(groupOption.Use) != 0 {
		PDs, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		// if test URL is empty, use the first health check URL of providers
		if groupOption.URL == "" {
			for _, pd := range PDs {
				if pd.HealthCheckURL() != "" {
					groupOption.URL = pd.HealthCheckURL()
					break
				}
			}
			if groupOption.URL == "" {
				groupOption.URL = C.DefaultTestURL
			}
		} else {
			addTestUrlToProviders(PDs, groupOption.URL, expectedStatus, groupOption.Filter, uint(groupOption.Interval))
		}
		providers = append(providers, PDs...)
	}

	if len(groupOption.Proxies) != 0 || members.Len() != 0 || libraryMembers.Len() != 0 {
		named, err := getProxiesFrom(lookup, groupOption.Proxies)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}
		ps := C.ConcatProxyLists(members, C.ProxySlice(named), libraryMembers)

		if _, ok := providersMap[groupName]; ok {
			return nil, fmt.Errorf("%s: %w", groupName, errDuplicateProvider)
		}

		if groupOption.URL == "" {
			groupOption.URL = C.DefaultTestURL
		}

		// select don't need auto health check
		if groupOption.Type != "select" && groupOption.Type != "relay" {
			if groupOption.Interval == 0 {
				groupOption.Interval = 300
			}
		}

		hc := provider.NewHealthCheckList(ps, groupOption.URL, uint(groupOption.TestTimeout), uint(groupOption.Interval), groupOption.Lazy, expectedStatus)

		pd, err := provider.NewCompatibleProviderList(groupName, ps, hc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		providers = append([]P.ProxyProvider{pd}, providers...)
		providersMap[groupName] = pd
	}

	switch groupOption.Type {
	case "url-test":
		opt := URLTestOption{}
		err = decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewURLTest(groupOption, opt, emptyFallback, providers)
	case "select":
		opt := SelectorOption{}
		err = decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewSelector(groupOption, opt, emptyFallback, providers)
	case "fallback":
		opt := FallbackOption{}
		err = decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewFallback(groupOption, opt, emptyFallback, providers)
	case "load-balance":
		opt := LoadBalanceOption{}
		err = decoder.Decode(config, &opt)
		if err != nil {
			return nil, err
		}
		return NewLoadBalance(groupOption, opt, emptyFallback, providers)
	case "relay":
		return nil, fmt.Errorf("%w: The group [%s] with relay type was removed, please using dialer-proxy instead", errType, groupName)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	return getProxiesFrom(func(name string) (C.Proxy, bool) { p, ok := mapping[name]; return p, ok }, list)
}

func getProxiesFrom(lookup func(string) (C.Proxy, bool), list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := lookup(name)
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]P.ProxyProvider, list []string) ([]P.ProxyProvider, error) {
	var ps []P.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == P.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func addTestUrlToProviders(providers []P.ProxyProvider, url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	if len(providers) == 0 || len(url) == 0 {
		return
	}

	for _, pd := range providers {
		pd.RegisterHealthCheckTask(url, expectedStatus, filter, interval)
	}
}
