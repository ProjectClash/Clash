package clash

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/dns"
	"go.yaml.in/yaml/v3"
)

func RenameReferencesForIOS(original, kind, oldName, newName string) (*StringBox, error) {
	out, err := recoverAppCall("RenameReferencesForIOS", func() (*StringBox, error) {
		return renameReferencesForIOSUnguarded(original, kind, oldName, newName)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type renameReferencesResult struct {
	OK      bool   `json:"ok"`
	Text    string `json:"text,omitempty"`
	Changed int    `json:"changed,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func renameReferencesForIOSUnguarded(original, kind, oldName, newName string) (*StringBox, error) {
	text, changed, err := renameReferences(original, kind, oldName, newName)
	result := renameReferencesResult{OK: true, Text: text, Changed: changed}
	if err != nil {
		var refusal *yamlEditError
		if !asYAMLEditError(err, &refusal) {
			return nil, bridgeSafeError(err)
		}
		result = renameReferencesResult{Code: refusal.code, Message: bridgeSafeString(refusal.message)}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

func asYAMLEditError(err error, target **yamlEditError) bool {
	refusal, ok := err.(*yamlEditError)
	if ok {
		*target = refusal
	}
	return ok
}

type renameEdit struct {
	node  *yaml.Node
	isKey bool
	value string
	flow  bool
}

var builtinPolicyNames = &lazyValue[map[string]bool]{build: func() map[string]bool {
	return map[string]bool{
		"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "PASS-RULE": true, "COMPATIBLE": true, "GLOBAL": true,
	}
}}

func renameReferences(original, kind, oldName, newName string) (string, int, error) {
	if err := validRenameName(kind, oldName, newName); err != nil {
		return "", 0, err
	}
	parsed, refusal := parseYAMLForEditCached(original)
	if refusal != nil {
		return "", 0, refusal
	}
	if parsed.aliases {
		return "", 0, refuseEdit("anchor", "the configuration holds anchors or aliases")
	}
	if node := caseAmbiguousField(parsed.root); node != nil {
		return "", 0, refuseEdit("unsafeReference", "line %d writes the field %q twice in different cases", node.Line, node.Value)
	}
	edits, refusal := planRenameReferences(parsed.root, kind, oldName, newName)
	if refusal != nil {
		return "", 0, refusal
	}
	inFlow := flowNodes(parsed.root)
	for i := range edits {
		edits[i].flow = inFlow[edits[i].node]
	}
	document := parsed.document()
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].node.Line != edits[j].node.Line {
			return edits[i].node.Line > edits[j].node.Line
		}
		return edits[i].node.Column > edits[j].node.Column
	})
	for _, edit := range edits {
		if refusal := document.replaceScalar(edit); refusal != nil {
			return "", 0, refusal
		}
	}
	expected, err := expectedAfterRename(parsed.root, edits)
	if err != nil {
		return "", 0, refuseEdit("invalidRequest", "the configuration does not parse: %v", err)
	}
	edited := document.text()
	if yamlEditSurgeryFault != nil {
		edited = yamlEditSurgeryFault(edited)
	}
	after, err := parseYAMLForCheck(edited)
	if err != nil {
		return "", 0, refuseEdit("unsafeEdit", "the edited text does not parse: %v", err)
	}
	value, err := after.decoded()
	if err != nil || !reflect.DeepEqual(value, expected) {
		return "", 0, refuseEdit("unsafeEdit", "the edited text would not mean exactly the requested renaming")
	}
	if after.editable {
		rememberParsedYAML(after)
	}
	return edited, len(edits), nil
}

func validRenameName(kind, oldName, newName string) *yamlEditError {
	forbidden := map[string]string{
		"ruleProvider":  ",:()",
		"proxyProvider": ",",
		"proxyGroup":    ",#&=",
		"proxy":         ",#&=",
	}
	characters, known := forbidden[kind]
	if !known {
		return refuseEdit("invalidRequest", "unknown kind %q", kind)
	}
	if oldName == "" || newName == "" || oldName == newName {
		return refuseEdit("invalidRequest", "both names are needed, and they must differ")
	}
	if strings.ContainsAny(newName, characters) || strings.IndexFunc(newName, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 ||
		strings.TrimSpace(newName) != newName || !utf8.ValidString(newName) {
		return refuseEdit("invalidRequest", "the new name cannot be written in every place it goes")
	}
	if (kind == "proxyGroup" || kind == "proxy") && (builtinPolicyNames.get()[strings.ToUpper(newName)] || strings.EqualFold(newName, dns.RespectRules)) {
		return refuseEdit("invalidRequest", "%q is a built-in policy", newName)
	}
	if kind == "proxyProvider" && newName == provider.ReservedName {
		return refuseEdit("invalidRequest", "%q is a reserved provider name", newName)
	}
	return nil
}

func structField(node *yaml.Node, key string, underscores bool) *yaml.Node {
	if value := mappingValue(node, key); value != nil || node == nil || node.Kind != yaml.MappingNode {
		return value
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		written := node.Content[i].Value
		if underscores {
			written = strings.ReplaceAll(written, "_", "-")
		}
		if strings.EqualFold(written, key) {
			return node.Content[i+1]
		}
	}
	return nil
}

func providerField(node *yaml.Node, key string) *yaml.Node { return structField(node, key, false) }
func groupField(node *yaml.Node, key string) *yaml.Node    { return structField(node, key, false) }
func proxyField(node *yaml.Node, key string) *yaml.Node    { return structField(node, key, true) }
func listenerField(node *yaml.Node, key string) *yaml.Node { return structField(node, key, true) }

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func mappingKey(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i]
		}
	}
	return nil
}

func sequenceItems(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

func mappingValues(node *yaml.Node) []*yaml.Node {
	var values []*yaml.Node
	if node == nil || node.Kind != yaml.MappingNode {
		return values
	}
	for i := 1; i < len(node.Content); i += 2 {
		values = append(values, node.Content[i])
	}
	return values
}

func planRenameReferences(root *yaml.Node, kind, oldName, newName string) ([]renameEdit, *yamlEditError) {
	var edits []renameEdit
	scalar := func(node *yaml.Node, value string) {
		if node != nil && node.Kind == yaml.ScalarNode && node.Value != value {
			edits = append(edits, renameEdit{node: node, value: value})
		}
	}
	rules := func(each func(*yaml.Node)) {
		for _, item := range sequenceItems(mappingValue(root, "rules")) {
			each(item)
		}
		for _, list := range mappingValues(mappingValue(root, "sub-rules")) {
			for _, item := range sequenceItems(list) {
				each(item)
			}
		}
	}
	switch kind {
	case "ruleProvider":
		providers := mappingValue(root, "rule-providers")
		key := mappingKey(providers, oldName)
		if key == nil {
			return nil, refuseEdit("notFound", "no rule provider %q", oldName)
		}
		if mappingKey(providers, newName) != nil {
			return nil, refuseEdit("invalidRequest", "a rule provider %q exists", newName)
		}
		edits = append(edits, renameEdit{node: key, isKey: true, value: newName})
		rules(func(item *yaml.Node) {
			if renamed, changed := renameRuleSetInRule(item.Value, oldName, newName, true); changed {
				scalar(item, renamed)
			}
		})
		for _, ruleProvider := range mappingValues(providers) {
			if behavior := providerField(ruleProvider, "behavior"); behavior == nil || !strings.EqualFold(behavior.Value, "classical") {
				continue
			}
			for _, item := range sequenceItems(providerField(ruleProvider, "payload")) {
				if renamed, changed := renameRuleSetInRule(item.Value, oldName, newName, false); changed {
					scalar(item, renamed)
				}
			}
		}
		dns := mappingValue(root, "dns")
		for _, field := range []string{"nameserver-policy", "proxy-server-nameserver-policy"} {
			policy := mappingValue(dns, field)
			if policy == nil || policy.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(policy.Content); i += 2 {
				if renamed, changed := renameRuleSetList(policy.Content[i].Value, oldName, newName, true); changed {
					if mappingKey(policy, renamed) != nil {
						return nil, refuseEdit("invalidRequest", "%s already has %q", field, renamed)
					}
					edits = append(edits, renameEdit{node: policy.Content[i], isKey: true, value: renamed})
				}
			}
		}
		fakeIPRules := false
		if mode := mappingValue(dns, "fake-ip-filter-mode"); mode != nil {
			fakeIPRules = strings.EqualFold(mode.Value, "rule")
		}
		for _, item := range sequenceItems(mappingValue(dns, "fake-ip-filter")) {
			if fakeIPRules {
				if renamed, changed := renameRuleSetInRule(item.Value, oldName, newName, true); changed {
					scalar(item, renamed)
				}
			} else if renamed, changed := renameRuleSetList(item.Value, oldName, newName, false); changed {
				scalar(item, renamed)
			}
		}
		var lists []*yaml.Node
		sniffer := mappingValue(root, "sniffer")
		for _, field := range []string{"force-domain", "skip-domain", "skip-src-address", "skip-dst-address"} {
			lists = append(lists, mappingValue(sniffer, field))
		}
		for _, list := range lists {
			for _, item := range sequenceItems(list) {
				if renamed, changed := renameRuleSetList(item.Value, oldName, newName, false); changed {
					scalar(item, renamed)
				}
			}
		}
		routeSets := func(tun *yaml.Node, field func(*yaml.Node, string) *yaml.Node, refers func(*yaml.Node, string) bool) {
			for _, name := range []string{"route-address-set", "route-exclude-address-set"} {
				for _, item := range sequenceItems(field(tun, name)) {
					if refers(item, oldName) {
						scalar(item, newName)
					}
				}
			}
		}
		routeSets(mappingValue(root, "tun"), mappingValue, yamlRefersTo)
		for _, listener := range sequenceItems(mappingValue(root, "listeners")) {
			if kind := mappingValue(listener, "type"); kind != nil && kind.Value == "tun" {
				routeSets(listener, listenerField, structRefersTo)
			}
		}
	case "proxyProvider":
		providers := mappingValue(root, "proxy-providers")
		key := mappingKey(providers, oldName)
		if key == nil {
			return nil, refuseEdit("notFound", "no proxy provider %q", oldName)
		}
		if mappingKey(providers, newName) != nil {
			return nil, refuseEdit("invalidRequest", "a proxy provider %q exists", newName)
		}
		for _, group := range sequenceItems(mappingValue(root, "proxy-groups")) {
			if name := mappingValue(group, "name"); name != nil && name.Value == newName {
				return nil, refuseEdit("invalidRequest", "a proxy group %q exists", newName)
			}
		}
		edits = append(edits, renameEdit{node: key, isKey: true, value: newName})
		for _, group := range sequenceItems(mappingValue(root, "proxy-groups")) {
			for _, item := range sequenceItems(groupField(group, "use")) {
				if structRefersTo(item, oldName) {
					scalar(item, newName)
				}
			}
		}
	case "proxyGroup", "proxy":
		var definitions []*yaml.Node
		for _, group := range sequenceItems(mappingValue(root, "proxy-groups")) {
			name := mappingValue(group, "name")
			if yamlRefersTo(name, oldName) {
				definitions = append(definitions, name)
			}
			if name != nil && name.Value == newName {
				return nil, refuseEdit("invalidRequest", "a proxy group %q exists", newName)
			}
		}
		groups := len(definitions)
		for _, proxy := range sequenceItems(mappingValue(root, "proxies")) {
			name := proxyField(proxy, "name")
			if structRefersTo(name, oldName) {
				definitions = append(definitions, name)
			}
			if structRefersTo(name, newName) {
				return nil, refuseEdit("invalidRequest", "a proxy %q exists", newName)
			}
		}
		if kind == "proxyGroup" && mappingKey(mappingValue(root, "proxy-providers"), newName) != nil {
			return nil, refuseEdit("invalidRequest", "a proxy provider %q exists", newName)
		}
		if len(definitions) > 1 {
			return nil, refuseEdit("invalidRequest", "%q names more than one proxy or group", oldName)
		}
		var nameNode *yaml.Node
		switch {
		case kind == "proxyGroup" && groups == 1:
			nameNode = definitions[0]
		case kind == "proxy" && groups == 0 && len(definitions) == 1:
			nameNode = definitions[0]
		case kind == "proxy":
			return nil, refuseEdit("notFound", "no proxy %q", oldName)
		default:
			return nil, refuseEdit("notFound", "no proxy group %q", oldName)
		}
		proxyProviders := mappingValue(root, "proxy-providers")
		for i := 0; proxyProviders != nil && proxyProviders.Kind == yaml.MappingNode && i+1 < len(proxyProviders.Content); i += 2 {
			exprs := providerField(providerField(proxyProviders.Content[i+1], "override"), "override-expr")
			for index, expr := range sequenceItems(exprs) {
				if nodeMentions(expr, oldName) {
					return nil, refuseEdit("unsafeReference", "proxy-providers.%s.override.override-expr[%d] (line %d) names %q and cannot be rewritten",
						proxyProviders.Content[i].Value, index, expr.Line, oldName)
				}
			}
			if exprs != nil && exprs.Kind != yaml.SequenceNode && nodeMentions(exprs, oldName) {
				return nil, refuseEdit("unsafeReference", "proxy-providers.%s.override.override-expr (line %d) names %q and cannot be rewritten",
					proxyProviders.Content[i].Value, exprs.Line, oldName)
			}
		}
		scalar(nameNode, newName)
		for _, group := range sequenceItems(mappingValue(root, "proxy-groups")) {
			for _, item := range sequenceItems(groupField(group, "proxies")) {
				if structRefersTo(item, oldName) {
					scalar(item, newName)
				}
			}
			if node := groupField(group, "default-selected"); structRefersTo(node, oldName) {
				scalar(node, newName)
			}
			if node := groupField(group, "empty-fallback"); kind == "proxy" && structRefersTo(node, oldName) {
				scalar(node, newName)
			}
		}
		rules(func(item *yaml.Node) {
			if renamed, changed := renameRuleTarget(item.Value, oldName, newName); changed {
				scalar(item, renamed)
			}
		})
		yamlDialers := []*yaml.Node{mappingValue(mappingValue(root, "ntp"), "dialer-proxy")}
		var dialers []*yaml.Node
		for _, proxy := range sequenceItems(mappingValue(root, "proxies")) {
			dialers = append(dialers, proxyField(proxy, "dialer-proxy"))
		}
		for _, provider := range mappingValues(mappingValue(root, "proxy-providers")) {
			dialers = append(dialers, providerField(provider, "dialer-proxy"),
				providerField(providerField(provider, "override"), "dialer-proxy"), providerField(provider, "proxy"))
			for _, proxy := range sequenceItems(providerField(provider, "payload")) {
				dialers = append(dialers, proxyField(proxy, "dialer-proxy"))
			}
		}
		for _, provider := range mappingValues(mappingValue(root, "rule-providers")) {
			dialers = append(dialers, providerField(provider, "proxy"))
		}
		for _, listener := range sequenceItems(mappingValue(root, "listeners")) {
			dialers = append(dialers, listenerField(listener, "proxy"))
			for _, field := range []string{"reality-config", "res-tls", "jls-config", "tlsmirror-config", "realm-opts", "jls-upstream"} {
				dialers = append(dialers, listenerField(listenerField(listener, field), "proxy"))
			}
			shadowTLS := listenerField(listener, "shadow-tls")
			dialers = append(dialers, listenerField(listenerField(shadowTLS, "handshake"), "proxy"))
			for _, handshake := range mappingValues(listenerField(shadowTLS, "handshake-for-server-name")) {
				dialers = append(dialers, listenerField(handshake, "proxy"))
			}
		}
		for _, tunnel := range sequenceItems(mappingValue(root, "tunnels")) {
			if tunnel.Kind == yaml.ScalarNode {
				if renamed, changed := renameTunnelProxy(tunnel.Value, oldName, newName); changed {
					scalar(tunnel, renamed)
				}
				continue
			}
			yamlDialers = append(yamlDialers, mappingValue(tunnel, "proxy"))
		}
		for _, node := range dialers {
			if structRefersTo(node, oldName) {
				scalar(node, newName)
			}
		}
		for _, node := range yamlDialers {
			if yamlRefersTo(node, oldName) {
				scalar(node, newName)
			}
		}
		dns := mappingValue(root, "dns")
		var unsafeServer, unwritableServer *yaml.Node
		servers := func(node *yaml.Node) {
			items := sequenceItems(node)
			if node != nil && node.Kind == yaml.ScalarNode {
				items = []*yaml.Node{node}
			}
			for _, item := range items {
				renamed, changed, unsafe := renameServerProxy(item.Value, oldName, newName)
				if kind == "proxy" {
					hostRenamed, hostChanged, hostUnsafe, unwritable := renameServerHost(renamed, oldName, newName)
					renamed, changed, unsafe = hostRenamed, changed || hostChanged, unsafe || hostUnsafe
					if unwritable && unwritableServer == nil {
						unwritableServer = item
					}
				}
				if unsafe && unsafeServer == nil {
					unsafeServer = item
				}
				if changed {
					scalar(item, renamed)
				}
			}
		}
		for _, field := range []string{"nameserver", "fallback", "default-nameserver", "proxy-server-nameserver", "direct-nameserver"} {
			servers(mappingValue(dns, field))
		}
		for _, field := range []string{"nameserver-policy", "proxy-server-nameserver-policy"} {
			for _, value := range mappingValues(mappingValue(dns, field)) {
				servers(value)
			}
		}
		if unsafeServer != nil {
			return nil, refuseEdit("unsafeReference", "the DNS server %q (line %d) names %q in a way that cannot be rewritten", unsafeServer.Value, unsafeServer.Line, oldName)
		}
		if unwritableServer != nil {
			return nil, refuseEdit("invalidRequest", "the new name cannot be written as the host of the DNS server %q (line %d)", unwritableServer.Value, unwritableServer.Line)
		}
	}
	return edits, nil
}

func renameRuleSetInRule(rule, oldName, newName string, needTarget bool) (string, bool) {
	var found [][2]int
	findRuleSets(newRuleText(rule), needTarget, oldName, &found)
	if len(found) == 0 {
		return rule, false
	}
	sort.Slice(found, func(i, j int) bool { return found[i][0] > found[j][0] })
	for _, span := range found {
		rule = rule[:span[0]] + newName + rule[span[1]:]
	}
	return rule, true
}

type ruleText struct {
	s  string
	at []int
}

func newRuleText(s string) ruleText {
	at := make([]int, len(s))
	for i := range at {
		at[i] = i
	}
	return ruleText{s: s, at: at}
}

func (t ruleText) slice(i, j int) ruleText { return ruleText{s: t.s[i:j], at: t.at[i:j]} }

func (t ruleText) trimmed() ruleText {
	left := len(t.s) - len(strings.TrimLeftFunc(t.s, unicode.IsSpace))
	right := len(strings.TrimRightFunc(t.s, unicode.IsSpace))
	if right < left {
		right = left
	}
	return t.slice(left, right)
}

func (t ruleText) fields() (items []ruleText, commas []int) {
	start := 0
	for i := 0; i <= len(t.s); i++ {
		if i == len(t.s) || t.s[i] == ',' {
			items = append(items, t.slice(start, i).trimmed())
			if i < len(t.s) {
				commas = append(commas, i)
			}
			start = i + 1
		}
	}
	return items, commas
}

func (t ruleText) joined(items []ruleText, commas []int, from, to int) ruleText {
	var out ruleText
	for k := from; k < to; k++ {
		if k > from {
			out.s += ","
			out.at = append(out.at, t.at[commas[k-1]])
		}
		out.s += items[k].s
		out.at = append(out.at, items[k].at...)
	}
	return out
}

func findRuleSets(t ruleText, needTarget bool, oldName string, found *[][2]int) {
	items, commas := t.fields()
	if len(items) < 2 {
		return
	}
	switch tp := strings.ToUpper(items[0].s); tp {
	case "RULE-SET":
		name := items[1]
		if name.s == oldName && len(name.at) > 0 && name.at[0] >= 0 {
			*found = append(*found, [2]int{name.at[0], name.at[len(name.at)-1] + 1})
		}
	case "AND", "OR", "NOT", "SUB-RULE":
		if tp == "SUB-RULE" && !needTarget {
			return
		}
		end := len(items)
		if needTarget {
			end--
		}
		if end <= 1 {
			return
		}
		payload := t.joined(items, commas, 1, end)
		if tp == "SUB-RULE" {
			payload = ruleText{s: "(" + payload.s + ")", at: append(append([]int{-1}, payload.at...), -1)}
		}
		for _, condition := range logicConditions(payload) {
			findRuleSets(condition, false, oldName, found)
		}
	}
}

func logicConditions(payload ruleText) []ruleText {
	if !strings.HasPrefix(payload.s, "(") || !strings.HasSuffix(payload.s, ")") {
		return nil
	}
	var stack []int
	var ranges [][2]int
	for i, c := range payload.s {
		switch c {
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) == 0 {
				return nil
			}
			ranges = append(ranges, [2]int{stack[len(stack)-1], i})
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	var chosen [][2]int
	for _, r := range ranges {
		if r[0] == 0 && r[1] == len(payload.s)-1 {
			continue
		}
		contained := false
		for _, c := range chosen {
			if c[0] < r[0] && c[1] > r[1] {
				contained = true
				break
			}
		}
		if !contained {
			chosen = append(chosen, r)
		}
	}
	conditions := make([]ruleText, 0, len(chosen))
	for _, r := range chosen {
		conditions = append(conditions, payload.slice(r[0]+1, r[1]))
	}
	return conditions
}

func renameRuleTarget(rule, oldName, newName string) (string, bool) {
	items := strings.Split(rule, ",")
	if len(items) < 2 {
		return rule, false
	}
	index := 2
	switch strings.ToUpper(strings.TrimSpace(items[0])) {
	case "SUB-RULE":
		return rule, false
	case "MATCH":
		index = 1
	case "NOT", "OR", "AND", "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		index = len(items) - 1
	}
	if index >= len(items) || strings.TrimSpace(items[index]) != oldName {
		return rule, false
	}
	field := items[index]
	lead := field[:strings.Index(field, strings.TrimSpace(field))]
	items[index] = lead + newName + field[len(lead)+len(oldName):]
	return strings.Join(items, ","), true
}

func renameRuleSetList(value, oldName, newName string, policyKey bool) (string, bool) {
	const prefix = "rule-set:"
	if !strings.HasPrefix(strings.ToLower(value), prefix) {
		return value, false
	}
	rest := value[len(prefix):]
	if policyKey && !strings.Contains(rest, ",") {
		if rest != oldName {
			return value, false
		}
		return value[:len(prefix)] + newName, true
	}
	segment, tail := rest, ""
	if colon := strings.Index(rest, ":"); colon >= 0 {
		segment, tail = rest[:colon], rest[colon:]
	}
	names := strings.Split(segment, ",")
	changed := false
	for i, name := range names {
		if name == oldName {
			names[i] = newName
			changed = true
		}
	}
	return value[:len(prefix)] + strings.Join(names, ",") + tail, changed
}

func renameServerProxy(server, oldName, newName string) (renamed string, changed, unsafe bool) {
	hash := strings.Index(server, "#")
	if hash < 0 {
		return server, false, false
	}
	u, err := url.Parse(pureDNSServer(server))
	if err != nil {
		return server, false, false
	}
	proxyName := ""
	for _, part := range strings.Split(u.Fragment, "&") {
		if !strings.Contains(part, "=") {
			proxyName = part
		}
	}
	if proxyName != oldName {
		return server, false, false
	}
	parts := strings.Split(server[hash+1:], "&")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.Contains(parts[i], "=") {
			continue
		}
		if decoded, err := url.PathUnescape(parts[i]); err != nil || decoded != oldName {
			return server, false, true
		}
		parts[i] = strings.ReplaceAll(newName, "%", "%25")
		return server[:hash+1] + strings.Join(parts, "&"), true, false
	}
	return server, false, true
}

func renameServerHost(server, oldName, newName string) (renamed string, changed, unsafe, unwritable bool) {
	u, err := url.Parse(pureDNSServer(server))
	if err != nil || u.Host != oldName {
		return server, false, false, false
	}
	switch u.Scheme {
	case "ts", "tailscale", "et", "easytier":
	default:
		return server, false, false, false
	}
	start := strings.Index(server, "://")
	if start < 0 {
		return server, false, true, false
	}
	start += len("://")
	authority := server[start:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		start += at + 1
		authority = authority[at+1:]
	}
	if authority != oldName {
		return server, false, true, false
	}
	renamed = server[:start] + newName + server[start+len(oldName):]
	check, err := url.Parse(pureDNSServer(renamed))
	if err != nil || check.Scheme != u.Scheme || check.Host != newName || check.Fragment != u.Fragment {
		return server, false, false, true
	}
	return renamed, true, false, false
}

func pureDNSServer(server string) string {
	if server == "system" {
		return "system://"
	}
	if ip, err := netip.ParseAddr(server); err == nil {
		if ip.Is4() {
			return "udp://" + server
		}
		return "udp://[" + server + "]"
	}
	if strings.Contains(server, "://") {
		return server
	}
	return "udp://" + server
}

func nodeMentions(node *yaml.Node, name string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		return strings.Contains(node.Value, name)
	}
	for _, child := range node.Content {
		if nodeMentions(child, name) {
			return true
		}
	}
	return false
}

func renameTunnelProxy(tunnel, oldName, newName string) (string, bool) {
	items := strings.Split(tunnel, ",")
	if len(items) != 4 || strings.TrimSpace(items[3]) != oldName {
		return tunnel, false
	}
	items[3] = strings.Replace(items[3], oldName, newName, 1)
	return strings.Join(items, ","), true
}

func (d *yamlEditDocument) replaceScalar(edit renameEdit) *yamlEditError {
	node := edit.node
	line := d.lines[node.Line-1]
	var start, end int
	if edit.isKey {
		var properties, ok bool
		start, end, properties, ok = d.keyToken(node)
		if !ok || properties {
			return refuseEdit("unsupportedStyle", "a key to rename could not be rewritten in place")
		}
	} else {
		numeric := (node.Tag == "!!int" || node.Tag == "!!float") && node.Style == 0
		if node.Anchor != "" || (node.Tag != "!!str" && !numeric) || node.Style&(yaml.LiteralStyle|yaml.FoldedStyle|yaml.TaggedStyle) != 0 {
			return refuseEdit("unsupportedStyle", "a reference is not a plain or quoted string on one line")
		}
		start = byteOffsetOfColumn(line, node.Column)
		rest := line[start:]
		switch {
		case node.Style&yaml.DoubleQuotedStyle != 0:
			closing := closingQuote(rest, '"')
			if closing < 0 {
				return refuseEdit("unsupportedStyle", "a quoted reference runs over several lines")
			}
			end = start + closing + 1
		case node.Style&yaml.SingleQuotedStyle != 0:
			closing := closingQuote(rest, '\'')
			if closing < 0 {
				return refuseEdit("unsupportedStyle", "a quoted reference runs over several lines")
			}
			end = start + closing + 1
		default:
			if !strings.HasPrefix(rest, node.Value) {
				return refuseEdit("unsupportedStyle", "a reference runs over several lines")
			}
			end = start + len(node.Value)
		}
	}
	token := renderRenamedScalar(edit.value, node.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0, edit.isKey, edit.flow)
	d.lines[node.Line-1] = line[:start] + token + line[end:]
	return nil
}

func renderRenamedScalar(value string, quoted, isKey, flow bool) string {
	if !quoted && !strings.ContainsAny(value, "\"'\n") && plainReadsBack(value, isKey, flow) {
		return value
	}
	var encoded strings.Builder
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return strings.TrimSuffix(encoded.String(), "\n")
}

func plainReadsBack(value string, isKey, flow bool) bool {
	var probe string
	switch {
	case isKey && flow:
		probe = "{" + value + ": x}"
	case isKey:
		probe = value + ": x"
	case flow:
		probe = "[" + value + "]"
	default:
		probe = "x: " + value
	}
	var read any
	if yaml.Unmarshal([]byte(probe), &read) != nil {
		return false
	}
	switch got := read.(type) {
	case map[string]any:
		if isKey {
			_, ok := got[value]
			return ok && len(got) == 1
		}
		return got["x"] == value
	case []any:
		return len(got) == 1 && got[0] == value
	}
	return false
}

func flowNodes(root *yaml.Node) map[*yaml.Node]bool {
	marked := map[*yaml.Node]bool{}
	var walk func(*yaml.Node, bool)
	walk = func(node *yaml.Node, inside bool) {
		marked[node] = inside
		for _, child := range node.Content {
			walk(child, inside || node.Style&yaml.FlowStyle != 0)
		}
	}
	walk(root, false)
	return marked
}

func expectedAfterRename(root *yaml.Node, edits []renameEdit) (any, error) {
	copies := map[*yaml.Node]*yaml.Node{}
	var clone func(*yaml.Node) *yaml.Node
	clone = func(node *yaml.Node) *yaml.Node {
		copied := *node
		copied.Content = make([]*yaml.Node, len(node.Content))
		for i, child := range node.Content {
			copied.Content[i] = clone(child)
		}
		copies[node] = &copied
		return &copied
	}
	copied := clone(root)
	for _, edit := range edits {
		target := copies[edit.node]
		target.Value = edit.value
		target.Style = 0
		target.Tag = "!!str"
	}
	var value any
	if err := copied.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return normalizeYAMLValue(value), nil
}

func caseAmbiguousField(root *yaml.Node) *yaml.Node {
	var visit func(node *yaml.Node) *yaml.Node
	visit = func(node *yaml.Node) *yaml.Node {
		if node == nil {
			return nil
		}
		if node.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i+1 < len(node.Content); i += 2 {
				key := strings.ToLower(strings.ReplaceAll(node.Content[i].Value, "_", "-"))
				if seen[key] {
					return node.Content[i]
				}
				seen[key] = true
			}
		}
		for _, child := range node.Content {
			if found := visit(child); found != nil {
				return found
			}
		}
		return nil
	}
	for _, section := range []string{"proxies", "proxy-groups", "listeners"} {
		if found := visit(mappingValue(root, section)); found != nil {
			return found
		}
	}
	for _, section := range []string{"proxy-providers", "rule-providers"} {
		for _, definition := range mappingValues(mappingValue(root, section)) {
			if found := visit(definition); found != nil {
				return found
			}
		}
	}
	return nil
}

func yamlRefersTo(node *yaml.Node, name string) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Value == name
}

func structRefersTo(node *yaml.Node, name string) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	if node.ShortTag() == "!!str" {
		return node.Value == name
	}
	var value any
	if err := node.Decode(&value); err != nil {
		return false
	}
	text, ok := weakString(value)
	return ok && text == name
}
