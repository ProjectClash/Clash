package clash

import (
	"encoding/json"
	"fmt"
	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/rules/clashindex"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/component/mmdb"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	RB "github.com/ProjectClash/Clash/rules/bundle"
	RC "github.com/ProjectClash/Clash/rules/common"
	"github.com/ProjectClash/Clash/rules/logic"
	RP "github.com/ProjectClash/Clash/rules/provider"
	T "github.com/ProjectClash/Clash/tunnel"
	"go.yaml.in/yaml/v3"
)

func MatchRuleForIOS(document, resourceMapJSON, query string) (*StringBox, error) {
	out, err := recoverAppCall("MatchRuleForIOS", func() (*StringBox, error) {
		return matchRuleForIOSUnguarded(document, resourceMapJSON, query)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type matchRuleQuery struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     uint16 `json:"port"`
	Network  string `json:"network"`
	SrcIP    string `json:"srcIP"`
	SrcPort  uint16 `json:"srcPort"`
	InPort   uint16 `json:"inPort"`
	InName   string `json:"inName"`
	InType   string `json:"inType"`
	Protocol string `json:"protocol"`
}

type matchRuleResult struct {
	Matched   bool   `json:"matched"`
	Undecided bool   `json:"undecided,omitempty"`
	Index     *int   `json:"index,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Policy    string `json:"policy,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type errMatchUndecided struct{ reason string }

func matchRuleForIOSUnguarded(document, resourceMapJSON, query string) (*StringBox, error) {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return nil, fmt.Errorf("clash: call Setup before MatchRuleForIOS")
	}
	var q matchRuleQuery
	if err := json.Unmarshal([]byte(query), &q); err != nil {
		return nil, fmt.Errorf("clash: match query: %w", err)
	}
	metadata, err := matchRuleMetadata(q)
	if err != nil {
		return nil, err
	}
	var resources resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &resources); err != nil {
			return nil, fmt.Errorf("clash: resource map: %w", err)
		}
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(document), &root); err != nil {
		return nil, fmt.Errorf("clash: parse config: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	canonicalizeProviderDefinitionKeysInDocument(root)
	if err := rewriteProviders(root, "rule-providers", "rule", resources.ProviderPaths, providerNamespaceCollisions(root)); err != nil {
		return nil, err
	}

	appParseMu.Lock()
	defer appParseMu.Unlock()
	previousMode := geodata.GeodataMode()
	defer geodata.SetGeodataMode(previousMode)
	geodataMode, _ := root["geodata-mode"].(bool)
	geodata.SetGeodataMode(geodataMode)

	RP.SetTunnel(T.Tunnel)
	walk := &offlineRules{providers: map[string]P.RuleProvider{}, inPortKnown: q.InPort > 0, inNameKnown: q.InName != ""}
	if walk.protocol, walk.protocolKnown, err = matchRuleProtocol(q.Protocol); err != nil {
		return nil, err
	}
	defer walk.close()
	if err := walk.loadProviders(root); err != nil {
		return nil, err
	}
	if err := walk.loadDocument(root); err != nil {
		return nil, err
	}
	subRules := map[string][]C.Rule{}
	raw, _ := root["sub-rules"].(map[string]any)
	for name := range raw {
		if name == "" {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		subRules[name] = []C.Rule{}
	}
	{
		for name, list := range raw {
			lines, isList := list.([]any)
			if !isList && list != nil {
				return nil, fmt.Errorf("clash: parse config: sub-rules[%s] is not a list of rules", name)
			}
			for idx, line := range lines {
				text, _ := line.(string)
				rule, err := walk.parseLine(text, subRules)
				if err != nil {
					return nil, fmt.Errorf("sub-rules[%s][%d] [%s] error: %w", name, idx, text, err)
				}
				subRules[name] = append(subRules[name], rule)
			}
		}
	}
	if err := verifyOfflineSubRules(subRules); err != nil {
		return nil, err
	}
	lines, _ := root["rules"].([]any)
	var count int
	var at func(i int) (C.Rule, string)
	var indexed *clashindex.Index
	var before, after []string
	if ref, named := documentRuleIndexRef(root); named && len(lines) == 0 {
		before, after = ref.Prepend, ref.Append
		var err error
		if indexed, err = config.ClashOpenRuleIndex(ref); err != nil {
			return nil, err
		}
	}
	if indexed != nil {
		var err error
		if count, at, err = walk.indexedRules(indexed, before, after, subRules); err != nil {
			return nil, err
		}
	} else {
		texts := make([]string, len(lines))
		rules := make([]C.Rule, len(lines))
		for idx, line := range lines {
			texts[idx], _ = line.(string)
			rule, err := walk.parseLine(texts[idx], subRules)
			if err != nil {
				return nil, fmt.Errorf("rules[%d] [%s] error: %w", idx, texts[idx], err)
			}
			rules[idx] = rule
		}
		count, at = len(rules), func(i int) (C.Rule, string) { return rules[i], texts[i] }
	}
	if metadata.DstIP.IsValid() && !resolver.CurrentIPQueryPolicy().AllowsAddress(metadata.DstIP) {
		return encodeMatchRuleResult(matchRuleResult{Reason: "ipVersionRefused"})
	}
	if metadata.Host != "" {
		node, ok, err := walk.searchHosts(metadata.Host, true)
		if err != nil {
			return nil, err
		}
		if ok {
			metadata.Host = node.Domain
		}
		ip, found, err := walk.hostAddress(metadata.Host)
		if err != nil {
			return nil, err
		}
		if found {
			metadata.DstIP = ip
			walk.hostsResolved = true
		}
	}
	result := matchRuleResult{Policy: "DIRECT"}
	for idx := 0; idx < count; idx++ {
		rule, text := at(idx)
		matched, policy, undecided := walk.match(rule, metadata)
		if undecided != "" {
			index := idx
			result = matchRuleResult{Undecided: true, Index: &index, Rule: text, Reason: undecided}
			break
		}
		if matched && policy != "PASS" {
			index := idx
			result = matchRuleResult{Matched: true, Index: &index, Rule: text, Policy: policy}
			break
		}
	}
	return encodeMatchRuleResult(result)
}

func encodeMatchRuleResult(result matchRuleResult) (*StringBox, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return WrapString(string(encoded)), nil
}

func matchRuleMetadata(q matchRuleQuery) (*C.Metadata, error) {
	metadata := &C.Metadata{Host: strings.TrimSuffix(strings.TrimSpace(q.Host), "."), DstPort: q.Port, Type: C.TUN}
	switch strings.ToLower(q.Network) {
	case "", "tcp":
		metadata.NetWork = C.TCP
	case "udp":
		metadata.NetWork = C.UDP
	default:
		return nil, fmt.Errorf("clash: match query: network is tcp or udp")
	}
	if q.IP != "" {
		ip, err := netip.ParseAddr(q.IP)
		if err != nil {
			return nil, fmt.Errorf("clash: match query: %w", err)
		}
		metadata.DstIP = ip.Unmap()
	}
	if metadata.Host == "" && !metadata.DstIP.IsValid() {
		return nil, fmt.Errorf("clash: match query: a host or an ip is needed")
	}
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.Host, metadata.DstIP = "", ip.Unmap()
	}
	if q.SrcIP != "" {
		ip, err := netip.ParseAddr(q.SrcIP)
		if err != nil {
			return nil, fmt.Errorf("clash: match query: %w", err)
		}
		metadata.SrcIP = ip.Unmap()
	}
	metadata.SrcPort = q.SrcPort
	metadata.InPort, metadata.InName = q.InPort, q.InName
	if q.InType != "" {
		typ, err := C.ParseType(strings.ToUpper(strings.TrimSpace(q.InType)))
		if err != nil {
			return nil, fmt.Errorf("clash: match query: inType: %w", err)
		}
		metadata.Type = *typ
	}
	return metadata, nil
}

func matchRuleProtocol(protocol string) (answer string, known bool, err error) {
	switch upper := strings.ToUpper(strings.TrimSpace(protocol)); upper {
	case "":
		return "", false, nil
	case "OTHER":
		return "", true, nil
	case "TLS":
		return RC.ProtocolHTTPS, true, nil
	case RC.ProtocolHTTP, RC.ProtocolHTTPS, RC.ProtocolQUIC, RC.ProtocolSTUN:
		return upper, true, nil
	}
	return "", false, fmt.Errorf("clash: match query: protocol is HTTP, HTTPS, TLS, QUIC, STUN or other, not %q", protocol)
}

type offlineRules struct {
	providers   map[string]P.RuleProvider
	unavailable map[string]bool
	opened      []P.RuleProvider
	geodataOK   map[string]bool

	hostTree                 *trie.DomainTrie[resolver.HostValue]
	hostsResolved            bool
	findProcessOff           bool
	policies                 map[string]bool
	activeSets               map[string]bool
	definedSets              map[string]bool
	copies                   string
	copied                   int
	inPortKnown, inNameKnown bool
	protocol                 string
	protocolKnown            bool
}

func (w *offlineRules) loadDocument(root map[string]any) error {
	tree := trie.New[resolver.HostValue]()
	if localhost, err := resolver.NewHostValueByIPs([]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}); err == nil {
		_ = tree.Insert("localhost", localhost)
	}
	hosts, _ := root["hosts"].(map[string]any)
	for domain, raw := range hosts {
		values, err := utils.ToStringSlice(raw)
		if err != nil {
			return err
		}
		if len(values) == 1 && values[0] == "lan" {
			continue
		}
		value, err := resolver.NewHostValue(values)
		if err != nil {
			return fmt.Errorf("%s is not a valid value", raw)
		}
		if value.IsDomain {
			node := tree.Search(value.Domain)
			for seen := map[string]bool{}; node != nil && node.Data().IsDomain; node = tree.Search(node.Data().Domain) {
				if node.Data().Domain == domain || seen[node.Data().Domain] {
					return fmt.Errorf("%s, there is a cycle in domain name mapping", domain)
				}
				seen[node.Data().Domain] = true
			}
		}
		_ = tree.Insert(domain, value)
	}
	for domain := range hosts {
		seen := map[string]bool{}
		for name := domain; ; {
			node := tree.Search(name)
			if node == nil || !node.Data().IsDomain {
				break
			}
			if seen[name] {
				return fmt.Errorf("%s, there is a cycle in domain name mapping", domain)
			}
			seen[name] = true
			name = node.Data().Domain
		}
	}
	w.hostTree = tree
	if mode, _ := root["find-process-mode"].(string); strings.EqualFold(mode, "off") {
		w.findProcessOff = true
	}
	w.policies = map[string]bool{"GLOBAL": true}
	for name := range builtinProxies() {
		w.policies[name] = true
	}
	proxies, _ := root["proxies"].([]any)
	for _, item := range proxies {
		mapping, _ := item.(map[string]any)
		if name, ok := decodedProxyName(mapping); ok {
			w.policies[name] = true
		}
	}
	groups, _ := root["proxy-groups"].([]any)
	for _, item := range groups {
		if mapping, ok := item.(map[string]any); ok {
			if name, ok := mapping["name"].(string); ok {
				w.policies[name] = true
			}
		}
	}
	if reference, ok := root["x-clash-node-library"]; ok {
		library := ruleNames{targets: map[string]struct{}{}}
		addLibraryNames(library, reference)
		for name := range library.targets {
			w.policies[name] = true
		}
	}
	return nil
}

func (w *offlineRules) hostAddress(host string) (netip.Addr, bool, error) {
	node, ok, err := w.searchHosts(host, false)
	if err != nil || !ok || node == nil {
		return netip.Addr{}, false, err
	}
	policy := resolver.CurrentIPQueryPolicy()
	if policy == resolver.IPQueryLegacy {
		if len(node.IPs) == 0 {
			return netip.Addr{}, true, nil
		}
		return node.IPs[0].Unmap(), true, nil
	}
	var allowed []netip.Addr
	for _, ip := range node.IPs {
		if policy.AllowsAddress(ip) {
			allowed = append(allowed, ip.Unmap())
		}
	}
	if len(allowed) == 0 {
		return netip.Addr{}, true, nil
	}
	if policy == resolver.IPQueryPreferIPv4 || policy == resolver.IPQueryPreferIPv6 {
		for _, ip := range allowed {
			if ip.Is4() == (policy == resolver.IPQueryPreferIPv4) {
				return ip, true, nil
			}
		}
	}
	return allowed[0], true, nil
}

func (w *offlineRules) searchHosts(domain string, isDomain bool) (*resolver.HostValue, bool, error) {
	if value := w.hostTree.Search(domain); value != nil {
		hostValue := value.Data()
		seen := map[string]bool{}
		for {
			if isDomain && hostValue.IsDomain {
				return &hostValue, true, nil
			}
			if hostValue.Domain == "" {
				break
			}
			if seen[hostValue.Domain] {
				return nil, false, fmt.Errorf("%s, there is a cycle in domain name mapping", domain)
			}
			seen[hostValue.Domain] = true
			node := w.hostTree.Search(hostValue.Domain)
			if node == nil {
				break
			}
			hostValue = node.Data()
		}
		return &hostValue, isDomain == hostValue.IsDomain, nil
	}
	if !isDomain {
		system := resolver.NewHosts(trie.New[resolver.HostValue]())
		if value, ok := system.Search(domain, false); ok {
			return value, true, nil
		}
	}
	return nil, false, nil
}

func (w *offlineRules) geodataUsable(kind string) bool {
	if w.geodataOK == nil {
		w.geodataOK = map[string]bool{}
	}
	if ok, known := w.geodataOK[kind]; known {
		return ok
	}
	ok := false
	switch kind {
	case "geoip":
		if geodata.GeodataMode() {
			ok = fileExists(C.Path.GeoIP()) && geodata.Verify(C.GeoipName) == nil
		} else {
			ok = fileExists(C.Path.MMDB()) && mmdb.Verify(C.Path.MMDB())
		}
	case "asn":
		ok = fileExists(C.Path.ASN()) && mmdb.Verify(C.Path.ASN())
	}
	w.geodataOK[kind] = ok
	return ok
}

func (w *offlineRules) loadProviders(root map[string]any) error {
	w.unavailable = map[string]bool{}
	w.definedSets = map[string]bool{}
	raw, _ := root["rule-providers"].(map[string]any)
	for name := range raw {
		w.definedSets[name] = true
	}
	for name, value := range raw {
		mapping, _ := value.(map[string]any)
		if mapping == nil {
			continue
		}
		kind, _ := mapping["type"].(string)
		if strings.EqualFold(kind, "http") {
			w.unavailable[name] = true
			continue
		}
		if strings.EqualFold(kind, "file") {
			path, _ := mapping["path"].(string)
			if path == "" {
				w.unavailable[name] = true
				continue
			}
			resolved := C.Path.Resolve(path)
			if _, statErr := os.Lstat(resolved); !pathInsideDirectory(resolved, C.Path.HomeDir()) ||
				statErr == nil && !providerSourceContained(resolved, C.Path.HomeDir()) {
				return fmt.Errorf("parse rule provider %s error: %w", name, C.Path.ErrNotSafePath(resolved))
			}
			if !fileExists(resolved) {
				w.unavailable[name] = true
				continue
			}
			copied, err := w.privateCopy(C.Path.Resolve(path))
			if err != nil {
				w.unavailable[name] = true
				continue
			}
			copiedMapping := make(map[string]any, len(mapping))
			for key, value := range mapping {
				copiedMapping[key] = value
			}
			copiedMapping["path"] = copied
			mapping = copiedMapping
		}
		provider, err := RP.ParseRuleProvider(name, mapping, w.parseRule, RB.MakeBundleFile)
		if err != nil {
			return fmt.Errorf("parse rule provider %s error: %w", name, err)
		}
		w.opened = append(w.opened, provider)
		if err := provider.Initial(); err != nil {
			w.unavailable[name] = true
			continue
		}
		w.providers[name] = provider
	}
	return nil
}

func (w *offlineRules) close() {
	for _, provider := range w.opened {
		closeRuleProvider(provider)
	}
	if w.copies != "" {
		_ = os.RemoveAll(w.copies)
	}
}

func (w *offlineRules) privateCopy(path string) (string, error) {
	if w.copies == "" {
		dir, err := os.MkdirTemp(C.Path.HomeDir(), ".match-rule-")
		if err != nil {
			return "", err
		}
		w.copies = dir
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	w.copied++
	copied := filepath.Join(w.copies, fmt.Sprintf("%d-%s", w.copied, filepath.Base(path)))
	return copied, os.WriteFile(copied, data, 0o600)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func (w *offlineRules) indexedRules(index *clashindex.Index, before, after []string, subRules map[string][]C.Rule) (int, func(i int) (C.Rule, string), error) {
	k := len(before)
	first := make([]C.Rule, k)
	for i, line := range before {
		rule, err := w.parseLine(line, subRules)
		if err != nil {
			return 0, nil, fmt.Errorf("rules[%d] [%s] error: %w", i, line, err)
		}
		first[i] = rule
	}
	var failure error
	index.Targets(func(name string, at int) bool {
		if !w.policies[name] {
			line, _, _ := index.Written(at)
			failure = fmt.Errorf("rules[%d] [%s] error: proxy [%s] not found", k+at, line, name)
		}
		return failure == nil
	})
	if failure != nil {
		return 0, nil, failure
	}
	var others []C.Rule
	index.Others(func(i int, line string) bool {
		rule, err := w.parseLine(line, subRules)
		if err != nil {
			failure = fmt.Errorf("rules[%d] [%s] error: %w", k+i, line, err)
			return false
		}
		others = append(others, rule)
		return true
	})
	if failure != nil {
		return 0, nil, failure
	}
	table, err := index.Table(others)
	if err != nil {
		return 0, nil, err
	}
	n := k + table.Len()
	last := make([]C.Rule, len(after))
	for j, line := range after {
		rule, err := w.parseLine(line, subRules)
		if err != nil {
			return 0, nil, fmt.Errorf("rules[%d] [%s] error: %w", n+j, line, err)
		}
		last[j] = rule
	}
	return n + len(after), func(i int) (C.Rule, string) {
		if i < k {
			return first[i], before[i]
		}
		if i >= n {
			return last[i-n], after[i-n]
		}
		line, _, _ := index.Written(i - k)
		return table.At(i - k), line
	}, nil
}

func (w *offlineRules) parseLine(line string, subRules map[string][]C.Rule) (C.Rule, error) {
	tp, payload, target, params := RC.ParseRulePayload(line, true)
	if target == "" {
		return nil, fmt.Errorf("format invalid")
	}
	if !w.policies[target] {
		if tp != "SUB-RULE" {
			return nil, fmt.Errorf("proxy [%s] not found", target)
		} else if _, ok := subRules[target]; !ok {
			return nil, fmt.Errorf("sub-rule [%s] not found", target)
		}
	}
	rule, err := w.parseRule(tp, payload, target, params, subRules)
	if err != nil {
		return nil, err
	}
	for _, name := range rule.ProviderNames() {
		if !w.definedSets[name] {
			return nil, fmt.Errorf("rule set [%s] not found", name)
		}
	}
	return rule, nil
}

func (w *offlineRules) parseRule(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
	if tp != "MATCH" && payload == "" {
		return nil, fmt.Errorf("missing subsequent parameters: %s", tp)
	}
	switch tp {
	case "RULE-SET":
		isSrc, noResolve := RC.ParseParams(params)
		return &offlineRuleSet{walk: w, name: payload, adapter: target, isSrc: isSrc, noResolveIP: noResolve}, nil
	case "SUB-RULE":
		return logic.NewSubRule(payload, target, subRules, w.parseRule)
	case "AND":
		return logic.NewAND(payload, target, w.parseRule)
	case "OR":
		return logic.NewOR(payload, target, w.parseRule)
	case "NOT":
		return logic.NewNOT(payload, target, w.parseRule)
	case "GEOSITE":
		if !fileExists(C.Path.GeoSite()) {
			return undecidedRule{ruleType: C.GEOSITE, adapter: target, reason: "geodataUnavailable"}, nil
		}
		geodata.MarkGeoSiteVerified()
		rule, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil && !strings.Contains(err.Error(), "not found in") {
			return undecidedRule{ruleType: C.GEOSITE, adapter: target, reason: "geodataUnavailable"}, nil
		}
		return rule, err
	case "GEOIP", "SRC-GEOIP":
		if !strings.EqualFold(payload, "lan") && !w.geodataUsable("geoip") {
			return undecidedRule{ruleType: C.GEOIP, adapter: target, reason: "geodataUnavailable"}, nil
		}
	case "IP-ASN", "SRC-IP-ASN":
		if !w.geodataUsable("asn") {
			return undecidedRule{ruleType: C.IPASN, adapter: target, reason: "geodataUnavailable"}, nil
		}
	case "IN-NAME", "IN-PORT", "IN-USER", "DSCP", "UID":
		rule, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil {
			return nil, err
		}
		if (tp == "IN-PORT" && w.inPortKnown) || (tp == "IN-NAME" && w.inNameKnown) {
			return rule, nil
		}
		return undecidedRule{ruleType: C.InName, adapter: target, reason: "needsInbound"}, nil
	case "SUBNET", "CELLULAR-RADIO":
		rule, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil {
			return nil, err
		}
		return undecidedRule{ruleType: rule.RuleType(), adapter: target, reason: "needsNetwork"}, nil
	}
	return R.ParseRule(tp, payload, target, params, subRules)
}

func (w *offlineRules) match(rule C.Rule, metadata *C.Metadata) (matched bool, policy string, undecided string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			stop, ok := recovered.(errMatchUndecided)
			if !ok {
				panic(recovered)
			}
			matched, policy, undecided = false, "", stop.reason
		}
	}()
	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			if !w.hostsResolved && metadata.Host != "" && !metadata.DstIP.IsValid() {
				panic(errMatchUndecided{reason: "needsIP"})
			}
		},
		FindProcess: func() {
			if metadata.Process == "" && metadata.ProcessPath == "" {
				panic(errMatchUndecided{reason: "needsProcess"})
			}
		},
		CheckPassRule: func(adapterName string) bool { return adapterName == "PASS-RULE" },
		Protocol: func() string {
			if !w.protocolKnown {
				panic(errMatchUndecided{reason: "needsProtocol"})
			}
			return w.protocol
		},
	}
	if w.findProcessOff {
		helper.FindProcess = nil
	}
	matched, policy = rule.Match(metadata, helper)
	return matched, policy, ""
}

type offlineRuleSet struct {
	walk        *offlineRules
	name        string
	adapter     string
	isSrc       bool
	noResolveIP bool
}

func (rs *offlineRuleSet) RuleType() C.RuleType    { return C.RuleSet }
func (rs *offlineRuleSet) Adapter() string         { return rs.adapter }
func (rs *offlineRuleSet) Payload() string         { return rs.name }
func (rs *offlineRuleSet) ProviderNames() []string { return []string{rs.name} }
func (rs *offlineRuleSet) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	provider, ok := rs.walk.providers[rs.name]
	if !ok {
		if rs.walk.unavailable[rs.name] {
			panic(errMatchUndecided{reason: "ruleSetUnavailable"})
		}
		return false, ""
	}
	if rs.walk.activeSets[rs.name] {
		panic(errMatchUndecided{reason: "ruleSetLoop"})
	}
	if rs.walk.activeSets == nil {
		rs.walk.activeSets = map[string]bool{}
	}
	rs.walk.activeSets[rs.name] = true
	defer delete(rs.walk.activeSets, rs.name)
	if rs.isSrc {
		metadata.SwapSrcDst()
		defer metadata.SwapSrcDst()
		helper.ResolveIP = nil
	} else if rs.noResolveIP {
		helper.ResolveIP = nil
	}
	return provider.Match(metadata, helper), rs.adapter
}

type undecidedRule struct {
	ruleType C.RuleType
	adapter  string
	reason   string
}

func (r undecidedRule) RuleType() C.RuleType    { return r.ruleType }
func (r undecidedRule) Adapter() string         { return r.adapter }
func (r undecidedRule) Payload() string         { return "" }
func (r undecidedRule) ProviderNames() []string { return nil }
func (r undecidedRule) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	panic(errMatchUndecided{reason: r.reason})
}

func verifyOfflineSubRules(subRules map[string][]C.Rule) error {
	verified := map[string]bool{}
	var visit func(name string, path []string) error
	visit = func(name string, path []string) error {
		if verified[name] {
			return nil
		}
		path = append(path, name)
		for i, rule := range subRules[name] {
			if rule.RuleType() != C.SubRules {
				continue
			}
			if _, ok := subRules[rule.Adapter()]; !ok {
				return fmt.Errorf("sub-rule[%d:%s] error: [%s] not found", i, name, rule.Adapter())
			}
			if slices.Contains(path, rule.Adapter()) {
				return fmt.Errorf("sub-rule error: circular references [%s]", strings.Join(append(path, rule.Adapter()), "->"))
			}
			if err := visit(rule.Adapter(), path); err != nil {
				return err
			}
		}
		verified[name] = true
		return nil
	}
	for name := range subRules {
		if err := visit(name, nil); err != nil {
			return err
		}
	}
	return nil
}

func decodedProxyName(mapping map[string]any) (string, bool) {
	value, ok := mapping["name"]
	if !ok {
		for key, candidate := range mapping {
			if strings.EqualFold(strings.ReplaceAll(key, "_", "-"), "name") {
				value, ok = candidate, true
				break
			}
		}
	}
	if !ok {
		return "", false
	}
	return weakString(value)
}

func weakString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case int:
		return strconv.FormatInt(int64(v), 10), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case float64:
		return strconv.FormatFloat(v, 'E', -1, 64), true
	}
	return "", false
}
