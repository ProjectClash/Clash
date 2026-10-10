package clash

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/config"
	P "github.com/ProjectClash/Clash/constant/provider"
	"go.yaml.in/yaml/v3"
)

func CompileCheckForIOS(document, resourceMapJSON string) (*StringBox, error) {
	out, err := recoverAppCall("CompileCheckForIOS", func() (*StringBox, error) {
		return compileCheckForIOSUnguarded(document, resourceMapJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type compileCheckError struct {
	Message string `json:"message"`
	Section string `json:"section,omitempty"`
	Index   *int   `json:"index,omitempty"`
	Line    int    `json:"line,omitempty"`
}

type compileCheckResult struct {
	OK     bool                `json:"ok"`
	Errors []compileCheckError `json:"errors"`
}

func compileCheckForIOSUnguarded(document, resourceMapJSON string) (*StringBox, error) {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return nil, bridgeSafeError(fmt.Errorf("clash: call Setup before CompileCheckForIOS"))
	}
	var resources resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &resources); err != nil {
			return nil, bridgeSafeError(fmt.Errorf("clash: resource map: %w", err))
		}
	}
	result := compileCheckResult{OK: true, Errors: []compileCheckError{}}
	if linesAreTheDocuments, line, err := compileCheck(document, resources); err != nil {
		if strings.ContainsAny(document, "\r\u0085\u2028\u2029") {
			linesAreTheDocuments, line = false, 0
		}
		result = compileCheckResult{Errors: []compileCheckError{placeCompileError(document, err.Error(), linesAreTheDocuments, line)}}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

func compileCheck(document string, resources resourceMap) (bool, int, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(document), &root); err != nil {
		return true, 0, fmt.Errorf("clash: parse config: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	canonicalizeProviderDefinitionKeysInDocument(root)
	collisions := providerNamespaceCollisions(root)
	for _, namespace := range []struct{ section, kind string }{{"proxy-providers", "proxy"}, {"rule-providers", "rule"}} {
		if err := rewriteProviders(root, namespace.section, namespace.kind, resources.ProviderPaths, collisions); err != nil {
			return false, 0, err
		}
	}
	redirected, err := yaml.Marshal(root)
	if err != nil {
		return false, 0, fmt.Errorf("clash: encode checked document: %w", err)
	}

	appParseMu.Lock()
	defer appParseMu.Unlock()
	previousGeoSiteOnly, previousGeoIPOnly := geodata.CompiledGeoSiteOnly(), geodata.CompiledGeoIPOnly()
	defer func() {
		geodata.SetCompiledGeoSiteOnly(previousGeoSiteOnly)
		geodata.SetCompiledGeoIPOnly(previousGeoIPOnly)
	}()
	cfg, err := parseClosingEveryNode(string(redirected))
	if err != nil {
		message, line := readersLines(err.Error(), document, redirected)
		if message != err.Error() {
			return false, line, errors.New(message)
		}
		return false, line, err
	}
	closeCatalogObjects(cfg.Proxies, cfg.Providers)
	for _, provider := range cfg.RuleProviders {
		closeRuleProvider(provider)
	}
	return false, 0, nil
}

func parseClosingEveryNode(document string) (*config.Config, error) {
	var mu sync.Mutex
	var built []outbound.ProxyAdapter
	stopped := false
	stop := adapter.ClashObserveParsedProxies(func(proxy outbound.ProxyAdapter) {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			_ = proxy.Close()
			return
		}
		built = append(built, proxy)
	})
	defer func() {
		stop()
		mu.Lock()
		stopped = true
		closing := built
		mu.Unlock()
		for _, proxy := range closing {
			_ = proxy.Close()
		}
	}()
	return parseConfigForIOS(document, true)
}

func closeRuleProvider(provider P.RuleProvider) {
	if closer, ok := provider.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

var (
	compileTopLevelRule    = &lazyRegexp{expr: `^rules\[(\d+)\]`}
	compileGroupPrefix     = &lazyRegexp{expr: `^proxy group\[\d+\]: `}
	compileSubRuleSentence = &lazyRegexp{expr: `^(?:sub-rules\[|sub-rule\[|sub-rule error:|sub-rule name is empty)`}
	compileClashWrapper    = &lazyRegexp{expr: `^clash: [a-z][a-z -]*: `}
	compileYAMLLine        = &lazyRegexp{expr: `\bline (\d+)\b`}
	compileRuleText        = &lazyRegexp{expr: `^rules\[\d+\] \[(.*?)\] error`}
	compileNamedProxy      = &lazyRegexp{expr: `\b(?:proxy (?:group )?|ProxyGroup )(?:\[)?([^\s\]]+?)(?:\])?(?: is the duplicate| not found|: the duplicate|: duplicate group name)`}
	compileNamedProvider   = &lazyRegexp{expr: `\bproxy provider ([^\s]+) error`}
)

var (
	compileCopyEntry     = &lazyRegexp{expr: `^([ \t]+)line (\d+): (.*)$`}
	compileCopyTag       = &lazyRegexp{expr: `^cannot unmarshal (!![a-z]+)`}
	compileCopyDuplicate = &lazyRegexp{expr: `^(mapping key .* already defined) at line \d+$`}
)

func readersLines(message, document string, copied []byte) (string, int) {
	lines := strings.Split(message, "\n")
	list := -1
	for i, text := range lines {
		if strings.HasSuffix(text, "yaml: unmarshal errors:") {
			list = i
			break
		}
	}
	if list < 0 {
		return message, 0
	}
	var copyRoot, readerRoot yaml.Node
	parsed := yaml.Unmarshal(copied, &copyRoot) == nil && yaml.Unmarshal([]byte(document), &readerRoot) == nil
	first := 0
	for i := list + 1; i < len(lines); i++ {
		entry := compileCopyEntry.get().FindStringSubmatch(lines[i])
		if entry == nil {
			continue
		}
		indent, rest := entry[1], entry[3]
		if duplicate := compileCopyDuplicate.get().FindStringSubmatch(rest); duplicate != nil {
			rest = duplicate[1]
		}
		readers := 0
		if tag := compileCopyTag.get().FindStringSubmatch(rest); tag != nil && parsed {
			line, _ := strconv.Atoi(entry[2])
			if path, isKey, found := yamlPathAtLine(&copyRoot, line, tag[1]); found {
				readers = yamlLineOfPath(&readerRoot, path, isKey)
			}
		}
		if readers > 0 {
			lines[i] = indent + "line " + strconv.Itoa(readers) + ": " + rest
			if first == 0 {
				first = readers
			}
			continue
		}
		lines[i] = indent + rest
	}
	return strings.Join(lines, "\n"), first
}

type yamlStep struct {
	key     string
	index   int
	isIndex bool
}

func yamlPathAtLine(root *yaml.Node, line int, tag string) (path []yamlStep, isKey, found bool) {
	bestDepth := -1
	depths := map[int]bool{}
	matches := func(node *yaml.Node) bool {
		switch node.Kind {
		case yaml.MappingNode:
			return tag == "!!map"
		case yaml.SequenceNode:
			return tag == "!!seq"
		case yaml.ScalarNode:
			return node.ShortTag() == tag
		}
		return false
	}
	var walk func(node *yaml.Node, steps []yamlStep, key bool)
	walk = func(node *yaml.Node, steps []yamlStep, key bool) {
		if node.Line == line && len(steps) > 0 && matches(node) {
			depths[len(steps)] = true
			if !found || len(steps) < bestDepth || len(steps) == bestDepth && isKey && !key {
				bestDepth, isKey, found = len(steps), key, true
				path = append([]yamlStep(nil), steps...)
			}
		}
		switch node.Kind {
		case yaml.DocumentNode:
			for _, child := range node.Content {
				walk(child, steps, false)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				step := append(steps[:len(steps):len(steps)], yamlStep{key: node.Content[i].Value})
				walk(node.Content[i], step, true)
				walk(node.Content[i+1], step, false)
			}
		case yaml.SequenceNode:
			for i, child := range node.Content {
				walk(child, append(steps[:len(steps):len(steps)], yamlStep{index: i, isIndex: true}), false)
			}
		}
	}
	walk(root, nil, false)
	if len(depths) > 1 {
		return nil, false, false
	}
	return path, isKey, found
}

func yamlLineOfPath(root *yaml.Node, path []yamlStep, isKey bool) int {
	node := root
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	line := 0
	for n, step := range path {
		key, value := yamlStepInto(node, step, 0)
		if value == nil {
			return line
		}
		node, line = value, value.Line
		if n == len(path)-1 && isKey && key != nil {
			line = key.Line
		}
	}
	return line
}

func yamlStepInto(node *yaml.Node, step yamlStep, depth int) (*yaml.Node, *yaml.Node) {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	if node == nil || depth > 16 {
		return nil, nil
	}
	switch {
	case step.isIndex && node.Kind == yaml.SequenceNode:
		if step.index < len(node.Content) {
			return nil, node.Content[step.index]
		}
	case !step.isIndex && node.Kind == yaml.MappingNode:
		for _, exact := range []bool{true, false} {
			for i := 0; i+1 < len(node.Content); i += 2 {
				if written := node.Content[i].Value; written == step.key || !exact && strings.EqualFold(written, step.key) {
					return node.Content[i], node.Content[i+1]
				}
			}
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value != "<<" {
				continue
			}
			sources := []*yaml.Node{node.Content[i+1]}
			if merged := node.Content[i+1]; merged.Kind == yaml.SequenceNode {
				sources = merged.Content
			}
			for _, source := range sources {
				if key, value := yamlStepInto(source, step, depth+1); value != nil {
					return key, value
				}
			}
		}
	}
	return nil, nil
}

func placeCompileError(document, message string, linesAreTheDocuments bool, line int) compileCheckError {
	placed := compileCheckError{Message: bridgeSafeString(message)}
	if line > 0 {
		placed.Line = line
		return placed
	}
	outline, err := yamlOutline(document)
	sectionItem := func(section string, index int) {
		placed.Section, placed.Index = section, &index
		if err != nil {
			return
		}
		for _, s := range outline.Sections {
			if s.Key == section && index < len(s.Items) {
				placed.Line = s.Items[index].Start
			}
		}
	}
	sentence := message
	for {
		at := compileClashWrapper.get().FindStringIndex(sentence)
		if at == nil {
			break
		}
		sentence = sentence[at[1]:]
	}
	end := len(sentence)
	subRuleAt, ruleAt, groupAt := end, end, end
	if name, occurrence, ok := duplicateNodeName(document, sentence); ok {
		placeDuplicate(document, "proxies", name, occurrence, &placed)
		return placed
	}
	for _, form := range []struct{ prefix, suffix string }{
		{"proxy group ", ": the duplicate name"},
		{"ProxyGroup ", ": duplicate group name"},
	} {
		if strings.HasPrefix(sentence, form.prefix) && strings.HasSuffix(sentence, form.suffix) &&
			len(sentence) > len(form.prefix)+len(form.suffix) {
			name := sentence[len(form.prefix) : len(sentence)-len(form.suffix)]
			occurrence := 1
			if form.prefix == "ProxyGroup " {
				occurrence = 2
			}
			placeDuplicate(document, "proxy-groups", name, occurrence, &placed)
			return placed
		}
	}
	if compileSubRuleSentence.get().MatchString(sentence) {
		subRuleAt = 0
	}
	if compileGroupPrefix.get().MatchString(sentence) {
		groupAt = 0
	}
	ruleMatch := compileTopLevelRule.get().FindStringSubmatchIndex(sentence)
	if ruleMatch != nil {
		ruleAt = 0
	}
	switch {
	case ruleAt < subRuleAt && ruleAt < groupAt:
		index, _ := strconv.Atoi(sentence[ruleMatch[2]:ruleMatch[3]])
		placed.Section = "rules"
		if original, ok := readersRuleIndex(document, index, sentence); ok {
			sectionItem("rules", original)
		}
		return placed
	case subRuleAt < groupAt:
		placed.Section = "sub-rules"
		return placed
	case groupAt < end:
		placed.Section = "proxy-groups"
		if name, ok := failingGroupName(document, sentence); ok {
			placeByName(document, name, &placed)
			if placed.Section != "proxy-groups" {
				placed.Section, placed.Index, placed.Line = "proxy-groups", nil, 0
			}
		}
		return placed
	}
	if match := compileNamedProvider.get().FindStringSubmatch(message); match != nil {
		placed.Section = "proxy-providers"
		if err == nil {
			for _, s := range outline.Sections {
				if s.Key != "proxy-providers" {
					continue
				}
				for _, item := range s.Items {
					if item.Key == match[1] {
						placed.Line = item.Start
					}
				}
			}
		}
		return placed
	}
	if match := compileYAMLLine.get().FindStringSubmatch(message); match != nil {
		if linesAreTheDocuments {
			placed.Line, _ = strconv.Atoi(match[1])
		}
		return placed
	}
	if match := compileNamedProxy.get().FindStringSubmatch(message); match != nil {
		placeByName(document, match[1], &placed)
	}
	return placed
}

func readersRuleIndex(document string, index int, message string) (int, bool) {
	quoted := compileRuleText.get().FindStringSubmatch(message)
	var root map[string]any
	if quoted == nil || yaml.Unmarshal([]byte(document), &root) != nil {
		return 0, false
	}
	rules, _ := root["rules"].([]any)
	text := func(i int) string {
		rule, _ := rules[i].(string)
		return strings.TrimSpace(rule)
	}
	if index < len(rules) && text(index) == quoted[1] {
		return index, true
	}
	kept := -1
	for i := range rules {
		if ruleCarriesUID(text(i)) {
			continue
		}
		if kept++; kept == index {
			return i, text(i) == quoted[1]
		}
	}
	return 0, false
}

var builtinNodeNames = &lazyValue[map[string]bool]{build: func() map[string]bool {
	return map[string]bool{
		"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "COMPATIBLE": true, "PASS": true, "PASS-RULE": true,
	}
}}

func duplicateNodeName(document, sentence string) (string, int, bool) {
	const prefix, suffix = "proxy ", " is the duplicate name"
	if !strings.HasPrefix(sentence, prefix) || !strings.HasSuffix(sentence, suffix) || len(sentence) < len(prefix)+len(suffix) {
		return "", 0, false
	}
	name := sentence[len(prefix) : len(sentence)-len(suffix)]
	var root map[string]any
	if yaml.Unmarshal([]byte(document), &root) != nil {
		return "", 0, false
	}
	proxies, _ := root["proxies"].([]any)
	count := 0
	for _, raw := range proxies {
		entry, _ := raw.(map[string]any)
		if written, _ := entry["name"].(string); written == name {
			count++
		}
	}
	if builtinNodeNames.get()[name] {
		return name, 1, count >= 1
	}
	return name, 2, count >= 2
}

func placeDuplicate(document, section, name string, occurrence int, placed *compileCheckError) {
	placed.Section = section
	var root map[string]any
	if yaml.Unmarshal([]byte(document), &root) != nil {
		return
	}
	outline, err := yamlOutline(document)
	list, _ := root[section].([]any)
	seen := 0
	for index, raw := range list {
		entry, _ := raw.(map[string]any)
		if written, _ := entry["name"].(string); written != name {
			continue
		}
		if seen++; seen < occurrence {
			continue
		}
		i := index
		placed.Index = &i
		if err == nil {
			for _, s := range outline.Sections {
				if s.Key == section && index < len(s.Items) {
					placed.Line = s.Items[index].Start
				}
			}
		}
		return
	}
}

func failingGroupName(document, message string) (string, bool) {
	at := compileGroupPrefix.get().FindStringIndex(message)
	var root map[string]any
	if at == nil || yaml.Unmarshal([]byte(document), &root) != nil {
		return "", false
	}
	rest := message[at[1]:]
	best := ""
	groups, _ := root["proxy-groups"].([]any)
	for _, raw := range groups {
		entry, _ := raw.(map[string]any)
		name, _ := entry["name"].(string)
		if name != "" && strings.HasPrefix(rest, name+": ") && len(name) > len(best) {
			best = name
		}
	}
	return best, best != ""
}

func placeByName(document, name string, placed *compileCheckError) {
	var root map[string]any
	if yaml.Unmarshal([]byte(document), &root) != nil {
		return
	}
	outline, err := yamlOutline(document)
	for _, section := range []string{"proxies", "proxy-groups"} {
		list, _ := root[section].([]any)
		for index, raw := range list {
			entry, _ := raw.(map[string]any)
			if entryName, _ := entry["name"].(string); strings.TrimSpace(entryName) == name {
				i := index
				placed.Section, placed.Index = section, &i
				if err == nil {
					for _, s := range outline.Sections {
						if s.Key == section && index < len(s.Items) {
							placed.Line = s.Items[index].Start
						}
					}
				}
				return
			}
		}
	}
}
