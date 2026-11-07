package clash

import (
	"fmt"
	"strings"
	"sync"
)

var ipStackNodeTypes = []string{"masque", "openvpn", "wireguard", "zerotier"}

func ipStackModeRule(nodeType string) deviationRule {
	return deviationRule{
		field:     "proxies[" + nodeType + "].ip-stack.mode",
		ruleScan:  true,
		nodeKey:   true,
		category:  deviationForced,
		effective: "go: every node runs the go stack, whatever mode it names",
		reason:    "the go stack is the only stack this core carries a node's connections on",
		source: "adapter/outbound/clash_go_ip_stack.go newIPStack; bind/clash/go_ip_stack_darwin.go; " +
			"sing-box 1.15 protocol/wireguard (its endpoint runs sing-tun's stack on an in-memory device)",
		recoverable: false,
		mechanism: "newIPStack builds every node's stack with the factory bind/clash registers (SetGoIPStackFactory): " +
			"the go stack on an in-memory device; IPStackOption.Mode is normalized and validated, and nothing reads it after",
	}
}

func ipStackCongestionRule(nodeType string) deviationRule {
	return deviationRule{
		field:           "proxies[" + nodeType + "].ip-stack.congestion-controller",
		ruleScan:        true,
		nodeKey:         true,
		category:        deviationForced,
		effective:       "bbr: the go stack has no bbr3, and runs its bbr",
		reason:          "every node runs the go stack, which has bbr, cubic and reno; bbr3 is closest to its bbr",
		source:          "bind/clash/go_ip_stack_darwin.go newGoIPStack; bind/clash/go_stack_darwin.go goStackCongestion; third_party/sing-tun-go stack_go_tcp_cong.go",
		recoverable:     false,
		forcedValue:     "bbr",
		forcedFrom:      []string{"bbr3"},
		caseInsensitive: true,
		mechanism: "IPStackOption.CongestionController reaches newGoIPStack as GoIPStackOptions.CongestionController; " +
			"goStackCongestion lowercases and trims it and turns bbr3 into bbr before gotun.NewGo, which knows reno, cubic and bbr",
	}
}

var ipStackRules = sync.OnceValue(func() map[string]*deviationRule {
	rules := map[string]*deviationRule{}
	for i := range deviationRules {
		if deviationRules[i].nodeKey {
			rules[deviationRules[i].field] = &deviationRules[i]
		}
	}
	return rules
})

func ipStackNode(proxy map[string]any) (nodeType string, options map[string]any, ok bool) {
	kind, _ := proxy["type"].(string)
	kind = strings.ToLower(strings.TrimSpace(kind))
	for _, candidate := range ipStackNodeTypes {
		if kind == candidate {
			options, ok = proxyOption(proxy, "ip-stack").(map[string]any)
			return candidate, options, ok
		}
	}
	return "", nil, false
}

type ipStackTally struct {
	count int
	first string
	at    int
}

func (t *ipStackTally) add(n int, first string, at int) {
	if t.count == 0 || at < t.at {
		t.first, t.at = first, at
	}
	t.count += n
}

type ipStackWrite struct {
	field, key string
	value      any
}

func ipStackWrites(proxy map[string]any) []ipStackWrite {
	nodeType, options, ok := ipStackNode(proxy)
	if !ok {
		return nil
	}
	var writes []ipStackWrite
	for _, key := range []string{"mode", "congestion-controller"} {
		field := "proxies[" + nodeType + "].ip-stack." + key
		rule, value := ipStackRules()[field], proxyOption(options, key)
		if rule != nil && value != nil && !rule.runsAsWritten(renderDeviationValue(value)) {
			writes = append(writes, ipStackWrite{field: field, key: key, value: value})
		}
	}
	return writes
}

func ipStackKept(proxy map[string]any) map[string]any {
	writes := ipStackWrites(proxy)
	if len(writes) == 0 {
		return nil
	}
	options := make(map[string]any, len(writes))
	for _, write := range writes {
		options[write.key] = write.value
	}
	return map[string]any{"type": proxy["type"], "name": proxy["name"], "ip-stack": options}
}

func tallyIPStack(tallies map[string]*ipStackTally, proxy map[string]any, at int) {
	writes := ipStackWrites(proxy)
	if len(writes) == 0 {
		return
	}
	node := fmt.Sprintf("proxies[%d]", at)
	if name, _ := proxy["name"].(string); name != "" {
		node = fmt.Sprintf("%s (proxies[%d])", name, at)
	}
	for _, write := range writes {
		if tallies[write.field] == nil {
			tallies[write.field] = &ipStackTally{}
		}
		tallies[write.field].add(1, node+": "+renderDeviationValue(write.value), at)
	}
}

func inlinePlaces(library map[string]any, count int) []int {
	written, _ := library["inline-at"].([]any)
	if len(written) != count {
		return nil
	}
	places := make([]int, count)
	for i, raw := range written {
		place, whole := yamlWhole(raw)
		if !whole || place < 0 || (i > 0 && place <= places[i-1]) {
			return nil
		}
		places[i] = place
	}
	return places
}

func ipStackWrittenIn(list []any, held []int) map[string]any {
	tallies := map[string]*ipStackTally{}
	for _, at := range held {
		if proxy, _ := list[at].(map[string]any); proxy != nil {
			tallyIPStack(tallies, proxy, at)
		}
	}
	if len(tallies) == 0 {
		return nil
	}
	recorded := make(map[string]any, len(tallies))
	for field, tally := range tallies {
		recorded[field] = map[string]any{"count": tally.count, "first": tally.first, "at": tally.at}
	}
	return recorded
}

func ipStackNodeDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	tallies := map[string]*ipStackTally{}
	library, _ := root["x-clash-node-library"].(map[string]any)
	proxies, _ := root["proxies"].([]any)
	places := inlinePlaces(library, len(proxies))
	for k, entry := range proxies {
		proxy, _ := entry.(map[string]any)
		if proxy == nil {
			continue
		}
		at := k
		if places != nil {
			at = places[k]
		}
		tallyIPStack(tallies, proxy, at)
	}
	recorded, _ := library["ip-stack-written"].(map[string]any)
	for field, raw := range recorded {
		entry, _ := raw.(map[string]any)
		count := yamlCount(entry["count"])
		first, _ := entry["first"].(string)
		if count <= 0 || first == "" || ipStackRules()[field] == nil {
			continue
		}
		if tallies[field] == nil {
			tallies[field] = &ipStackTally{}
		}
		tallies[field].add(count, first, yamlCount(entry["at"]))
	}
	var reported []configDeviation
	for i := range deviationRules {
		rule := &deviationRules[i]
		tally := tallies[rule.field]
		if !rule.nodeKey || tally == nil || !rule.active(policy) {
			continue
		}
		given := tally.first
		if tally.count > 1 {
			given = fmt.Sprintf("%d nodes, the first %s", tally.count, tally.first)
		}
		reported = append(reported, configDeviation{
			Field:       rule.field,
			Given:       given,
			Effective:   rule.effective,
			Category:    rule.category,
			Reason:      rule.reason,
			Source:      rule.source,
			Recoverable: rule.recoverable,
			Alternative: rule.alternative,
			Mechanism:   rule.mechanism,
			Written:     true,
		})
	}
	return reported
}

func yamlCount(value any) int {
	n, _ := yamlWhole(value)
	return n
}

func yamlWhole(value any) (int, bool) {
	switch n := value.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		return int(n), n == float64(int(n))
	}
	return 0, false
}
