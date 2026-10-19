package clash

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
	"unsafe"

	RC "github.com/ProjectClash/Clash/rules/common"
	"go.yaml.in/yaml/v3"
)

var ErrRuleCatalogUnreadable = errors.New("clash: the rules of this configuration cannot be read one at a time")

var ErrRuleCatalogIsPublished = errors.New("clash: these rules are compiled into a rule index; this configuration is a published one")

type RuleCatalog struct {
	mu      sync.RWMutex
	text    string
	mapping []byte
	items   []ruleCatalogItem
	blocks  map[int]string
	found   bool
	flow    bool
	end     int
}

type ruleCatalogItem struct {
	start, end uint32
	style      uint8
	verbatim   bool
}

func OpenRuleCatalogForIOS(document string) (*RuleCatalog, error) {
	out, err := recoverAppCall("OpenRuleCatalogForIOS", func() (*RuleCatalog, error) { return openRuleCatalog(document) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func openRuleCatalog(document string) (*RuleCatalog, error) {
	if len(document) > 1<<32-1 {
		return nil, ErrRuleCatalogUnreadable
	}
	c := &RuleCatalog{text: document}
	in := unsafe.Slice(unsafe.StringData(document), len(document))
	defer enterCompactHeap()()
	scan, ok := yaml.ClashScanSequence(in, "rules", func(item yaml.ClashItem) bool {
		verbatim := item.Style == yaml.ClashPlain && string(item.Value) == document[item.Start:item.End]
		if item.Style == yaml.ClashLiteral || item.Style == yaml.ClashFolded {
			if c.blocks == nil {
				c.blocks = map[int]string{}
			}
			c.blocks[len(c.items)] = string(item.Value)
		}
		c.items = append(c.items, ruleCatalogItem{start: uint32(item.Start), end: uint32(item.End), style: uint8(item.Style), verbatim: verbatim})
		return true
	})
	if !ok {
		return nil, ErrRuleCatalogUnreadable
	}
	c.found, c.flow, c.end = scan.Found, scan.Flow, scan.End
	if !c.found && (strings.HasPrefix(document, "x-clash-rule-index:") || strings.Contains(document, "\nx-clash-rule-index:")) {
		return nil, ErrRuleCatalogIsPublished
	}
	return c, nil
}

func (c *RuleCatalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mapping != nil {
		_ = syscall.Munmap(c.mapping)
		c.mapping = nil
	}
	c.text, c.items, c.blocks = "", nil, nil
}

func (c *RuleCatalog) Total() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int32(len(c.items))
}

func (c *RuleCatalog) written(i int) string {
	return c.text[c.items[i].start:c.items[i].end]
}

func (c *RuleCatalog) value(i int) string {
	raw := c.written(i)
	if c.items[i].verbatim {
		return raw
	}
	if value, ok := c.blocks[i]; ok {
		return value
	}
	var value string
	if err := yaml.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	return value
}

func ruleTypeAndTarget(rule string) (string, string, []string, string) {
	tp, payload, target, params := RC.ParseRulePayload(rule, true)
	return tp, target, params, payload
}

func ruleIsIndexed(tp, payload string, params []string) bool {
	switch tp {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		return payload != ""
	case "IP-CIDR", "IP-CIDR6":
		for _, param := range params {
			if param == RC.Src {
				return false
			}
		}
		return payload != ""
	}
	return false
}

type ruleSummary struct {
	Total        int            `json:"total"`
	IndexedTotal int            `json:"indexedTotal"`
	ObjectTotal  int            `json:"objectTotal"`
	ByType       map[string]int `json:"byType"`
	ByTarget     map[string]int `json:"byTarget"`
	MatchTarget  string         `json:"matchTarget,omitempty"`
	RuleSets     []string       `json:"ruleSets"`
	SubRules     []string       `json:"subRules"`
	UIDRemoved   int            `json:"uidRemoved"`
	Prepended    int            `json:"prepended,omitempty"`
	Appended     int            `json:"appended,omitempty"`
}

func (c *RuleCatalog) SummaryJSON() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return bridgeSafeString(summarizeRules(len(c.items), 0, func(i int) (string, string, string, bool) {
		tp, target, params, payload := ruleTypeAndTarget(c.value(i))
		return tp, target, payload, ruleIsIndexed(tp, payload, params)
	}))
}

func summarizeRules(n, uidRemoved int, rule func(i int) (tp, target, payload string, indexed bool)) string {
	return summarizeRulesBefore(n, uidRemoved, 0, 0, rule)
}

func summarizeRulesBefore(n, uidRemoved, prepended, appended int, rule func(i int) (tp, target, payload string, indexed bool)) string {
	s := ruleSummary{Total: n, UIDRemoved: uidRemoved, Prepended: prepended, Appended: appended, ByType: map[string]int{}, ByTarget: map[string]int{}, RuleSets: []string{}, SubRules: []string{}}
	ruleSets, subRules := map[string]bool{}, map[string]bool{}
	for i := 0; i < n; i++ {
		tp, target, payload, indexed := rule(i)
		s.ByType[tp]++
		if target != "" {
			s.ByTarget[target]++
		}
		if indexed {
			s.IndexedTotal++
		}
		switch tp {
		case "MATCH":
			s.MatchTarget = target
		case "RULE-SET":
			ruleSets[payload] = true
		case "SUB-RULE":
			subRules[target] = true
		}
	}
	s.ObjectTotal = s.Total - s.IndexedTotal
	for name := range ruleSets {
		s.RuleSets = append(s.RuleSets, name)
	}
	for name := range subRules {
		s.SubRules = append(s.SubRules, name)
	}
	sort.Strings(s.RuleSets)
	sort.Strings(s.SubRules)
	b, _ := json.Marshal(s)
	return bridgeSafeString(string(b))
}

type rulePageEntry struct {
	Index  int    `json:"index"`
	Text   string `json:"text"`
	Rule   string `json:"rule"`
	Type   string `json:"type"`
	Target string `json:"target"`
}

type rulePage struct {
	Total   int             `json:"total"`
	Matched int             `json:"matched"`
	Offset  int             `json:"offset"`
	Rules   []rulePageEntry `json:"rules"`
	Error   string          `json:"error,omitempty"`
}

const rulePageMost = 500

func (c *RuleCatalog) PageJSON(offset, limit int32, query, target, typesJSON string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	filter, err := parseRuleFilter(query, target, typesJSON)
	return bridgeSafeString(pageRules(len(c.items), offset, limit, filter, err, func(i int) bool {
		rule := c.value(i)
		if filter.folded != "" && !containsFolded(rule, filter.folded) {
			return false
		}
		tp, ruleTarget, _, _ := ruleTypeAndTarget(rule)
		return filter.keepsKind(tp, ruleTarget)
	}, func(i int) rulePageEntry {
		rule := c.value(i)
		tp, ruleTarget, _, _ := ruleTypeAndTarget(rule)
		return rulePageEntry{Index: i, Text: c.written(i), Rule: rule, Type: tp, Target: ruleTarget}
	}))
}

type ruleFilter struct {
	folded string
	target string
	types  map[string]bool
}

func parseRuleFilter(query, target, typesJSON string) (ruleFilter, error) {
	f := ruleFilter{folded: strings.ToLower(query), target: target}
	if strings.TrimSpace(typesJSON) == "" {
		return f, nil
	}
	var types []string
	if err := json.Unmarshal([]byte(typesJSON), &types); err != nil {
		return f, fmt.Errorf("clash: types is not a JSON array of rule types: %w", err)
	}
	for _, tp := range types {
		if f.types == nil {
			f.types = map[string]bool{}
		}
		f.types[strings.ToUpper(strings.TrimSpace(tp))] = true
	}
	return f, nil
}

func (f ruleFilter) any() bool { return f.folded != "" || f.target != "" || f.types != nil }

func (f ruleFilter) keepsKind(tp, target string) bool {
	return (f.types == nil || f.types[tp]) && (f.target == "" || f.target == target)
}

func pageRules(n int, offset, limit int32, filter ruleFilter, filterErr error, keep func(i int) bool, entry func(i int) rulePageEntry) string {
	if limit <= 0 || limit > rulePageMost {
		limit = rulePageMost
	}
	if offset < 0 {
		offset = 0
	}
	page := rulePage{Total: n, Offset: int(offset), Rules: []rulePageEntry{}}
	switch {
	case filterErr != nil:
		page.Offset, page.Error = 0, filterErr.Error()
	case !filter.any():
		page.Matched = n
		if page.Offset > page.Matched {
			page.Offset = page.Matched
		}
		for i := page.Offset; i < n && len(page.Rules) < int(limit); i++ {
			page.Rules = append(page.Rules, entry(i))
		}
	default:
		for i := 0; i < n; i++ {
			if !keep(i) {
				continue
			}
			if page.Matched >= int(offset) && len(page.Rules) < int(limit) {
				page.Rules = append(page.Rules, entry(i))
			}
			page.Matched++
		}
		if page.Offset > page.Matched {
			page.Offset = page.Matched
		}
	}
	b, _ := json.Marshal(page)
	return bridgeSafeString(string(b))
}

func containsFolded(s, folded string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return strings.Contains(strings.ToLower(s), folded)
		}
	}
	n := len(folded)
	for i := 0; i+n <= len(s); i++ {
		match := true
		for k := 0; k < n; k++ {
			b := s[i+k]
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != folded[k] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

type RuleEdit struct {
	Text              string
	FirstChangedIndex int32
	Total             int32
}

type ruleEditOp struct {
	Op    string `json:"op"`
	Index int    `json:"index"`
	To    int    `json:"to"`
	Rule  string `json:"rule"`
}

func (c *RuleCatalog) Edit(opsJSON string) (*RuleEdit, error) {
	out, err := recoverAppCall("RuleCatalog.Edit", func() (*RuleEdit, error) {
		c.mu.RLock()
		defer c.mu.RUnlock()
		return c.edit(opsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type ruleSegment struct {
	prefix, text, rest string
	style              yaml.ClashItemStyle
}

func (c *RuleCatalog) itemLine(i int) (prefix, text, rest string, ok bool) {
	start, end := int(c.items[i].start), int(c.items[i].end)
	lineStart := strings.LastIndexByte(c.text[:start], '\n') + 1
	prefix = c.text[lineStart:start]
	if trimmed := strings.TrimLeft(prefix, " \t"); trimmed == "" || trimmed[0] != '-' || strings.TrimSpace(trimmed[1:]) != "" {
		return "", "", "", false
	}
	if end > start && c.text[end-1] == '\n' {
		body := strings.TrimRight(c.text[start:end], "\r\n")
		rest := end
		if i+1 < len(c.items) {
			rest = strings.LastIndexByte(c.text[:c.items[i+1].start], '\n') + 1
		}
		return prefix, body, c.text[start+len(body) : rest], true
	}
	next := len(c.text)
	if i+1 < len(c.items) {
		next = strings.LastIndexByte(c.text[:c.items[i+1].start], '\n') + 1
	} else if nl := strings.IndexByte(c.text[end:], '\n'); nl >= 0 {
		next = end + nl + 1
	}
	return prefix, c.text[start:end], c.text[end:next], true
}

func (c *RuleCatalog) edit(opsJSON string) (*RuleEdit, error) {
	var b strings.Builder
	first, total, err := c.editTo(opsJSON, &b, true)
	if err != nil {
		return nil, err
	}
	return &RuleEdit{Text: b.String(), FirstChangedIndex: first, Total: total}, nil
}

type ruleWriter interface {
	WriteString(string) (int, error)
}

func (c *RuleCatalog) editTo(opsJSON string, b ruleWriter, grow bool) (int32, int32, error) {
	var ops []ruleEditOp
	if err := json.Unmarshal([]byte(opsJSON), &ops); err != nil {
		return 0, 0, fmt.Errorf("clash: rule edits: %w", err)
	}
	if c.flow {
		return 0, 0, errors.New("clash: these rules are written as a flow sequence; edit them as a whole")
	}
	text := c.text
	newline := "\n"
	list := make([]int32, len(c.items))
	for i := range c.items {
		list[i] = int32(i)
		if _, _, rest, ok := c.itemLine(i); !ok {
			return 0, 0, errors.New("clash: a rule does not start its own line; edit the rules as a whole")
		} else if i == 0 && strings.HasSuffix(rest, "\r\n") {
			newline = "\r\n"
		}
	}
	var written []ruleSegment
	segment := func(ref int32) ruleSegment {
		if ref < 0 {
			return written[-1-ref]
		}
		prefix, text, rest, _ := c.itemLine(int(ref))
		return ruleSegment{prefix: prefix, text: text, rest: rest, style: yaml.ClashItemStyle(c.items[ref].style)}
	}
	first := len(list)
	touched := func(i int) {
		if i < first {
			first = i
		}
	}
	template := func(at int) (string, yaml.ClashItemStyle) {
		switch {
		case at < len(list):
			s := segment(list[at])
			return s.prefix, s.style
		case len(list) > 0:
			s := segment(list[len(list)-1])
			return s.prefix, s.style
		}
		return "  - ", yaml.ClashPlain
	}
	for n, op := range ops {
		switch op.Op {
		case "insert":
			if op.Index < 0 || op.Index > len(list) {
				return 0, 0, fmt.Errorf("clash: rule edit %d: index %d out of range", n, op.Index)
			}
			prefix, style := template(op.Index)
			rule, err := writeRule(op.Rule, style)
			if err != nil {
				return 0, 0, err
			}
			written = append(written, ruleSegment{prefix: prefix, text: rule, rest: newline, style: style})
			list = append(list, 0)
			copy(list[op.Index+1:], list[op.Index:])
			list[op.Index] = int32(-len(written))
			touched(op.Index)
		case "replace":
			if op.Index < 0 || op.Index >= len(list) {
				return 0, 0, fmt.Errorf("clash: rule edit %d: index %d out of range", n, op.Index)
			}
			s := segment(list[op.Index])
			rule, err := writeRule(op.Rule, s.style)
			if err != nil {
				return 0, 0, err
			}
			s.text = rule
			written = append(written, s)
			list[op.Index] = int32(-len(written))
			touched(op.Index)
		case "delete":
			if op.Index < 0 || op.Index >= len(list) {
				return 0, 0, fmt.Errorf("clash: rule edit %d: index %d out of range", n, op.Index)
			}
			list = append(list[:op.Index], list[op.Index+1:]...)
			touched(op.Index)
		case "move":
			if op.Index < 0 || op.Index >= len(list) || op.To < 0 || op.To >= len(list) {
				return 0, 0, fmt.Errorf("clash: rule edit %d: index out of range", n)
			}
			moved := list[op.Index]
			list = append(list[:op.Index], list[op.Index+1:]...)
			list = append(list, 0)
			copy(list[op.To+1:], list[op.To:])
			list[op.To] = moved
			touched(min(op.Index, op.To))
		default:
			return 0, 0, fmt.Errorf("clash: rule edit %d: no op %q", n, op.Op)
		}
	}
	growBy := func(n int) {
		if builder, ok := b.(*strings.Builder); ok && grow {
			builder.Grow(n)
		}
	}
	if len(c.items) == 0 {
		if len(list) == 0 {
			_, err := b.WriteString(text)
			return 0, 0, err
		}
		if c.found || strings.Contains(text, "\nrules:") || strings.HasPrefix(text, "rules:") {
			return 0, 0, errors.New("clash: these rules are empty in a way only a whole edit can fill")
		}
		growBy(len(text) + 64*len(list))
		b.WriteString(text)
		if text != "" && !strings.HasSuffix(text, "\n") {
			b.WriteString(newline)
		}
		b.WriteString("rules:" + newline)
		for _, ref := range list {
			s := segment(ref)
			b.WriteString(s.prefix + s.text + s.rest)
		}
		_, err := b.WriteString("")
		return 0, int32(len(list)), err
	}
	from := strings.LastIndexByte(text[:c.items[0].start], '\n') + 1
	_, lastText, lastRest, _ := c.itemLine(len(c.items) - 1)
	to := int(c.items[len(c.items)-1].start) + len(lastText) + len(lastRest)
	growBy(len(text) + 64*len(ops))
	b.WriteString(text[:from])
	for i, ref := range list {
		s := segment(ref)
		if i < len(list)-1 && !strings.HasSuffix(s.rest, "\n") {
			s.text = stripChomping(s.text)
		}
		b.WriteString(s.prefix)
		b.WriteString(s.text)
		b.WriteString(s.rest)
		if i < len(list)-1 && !strings.HasSuffix(s.rest, "\n") {
			b.WriteString(newline)
		}
	}
	if first > len(list) {
		first = len(list)
	}
	if _, err := b.WriteString(text[to:]); err != nil {
		return 0, 0, err
	}
	return int32(first), int32(len(list)), nil
}

func stripChomping(text string) string {
	header, body, found := strings.Cut(text, "\n")
	if !found || header == "" || (header[0] != '|' && header[0] != '>') {
		return text
	}
	for _, lineBreak := range []string{"\r", "\u0085", "\u2028", "\u2029"} {
		if strings.HasSuffix(text, lineBreak) {
			return text
		}
	}
	indicators := header[1:]
	n := 0
	for n < len(indicators) && (indicators[n] == '+' || indicators[n] == '-' || indicators[n] >= '1' && indicators[n] <= '9') {
		n++
	}
	if strings.Contains(indicators[:n], "-") {
		return text
	}
	indent := strings.ReplaceAll(indicators[:n], "+", "")
	return header[:1] + indent + "-" + indicators[n:] + "\n" + body
}

func writeRule(rule string, style yaml.ClashItemStyle) (string, error) {
	if rule == "" || strings.ContainsAny(rule, "\r\n") && style != yaml.ClashDoubleQuoted {
		style = yaml.ClashDoubleQuoted
	}
	readsBack := func(written string) bool {
		var back []string
		return yaml.Unmarshal([]byte("- "+written+"\n"), &back) == nil && len(back) == 1 && back[0] == rule
	}
	if style == yaml.ClashPlain || style == yaml.ClashLiteral || style == yaml.ClashFolded {
		if readsBack(rule) {
			return rule, nil
		}
		style = yaml.ClashSingleQuoted
	}
	if style == yaml.ClashSingleQuoted {
		if written := "'" + strings.ReplaceAll(rule, "'", "''") + "'"; readsBack(written) {
			return written, nil
		}
	}
	encoded, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}
	written := strings.ReplaceAll(string(encoded), `<`, "<")
	written = strings.ReplaceAll(written, `>`, ">")
	written = strings.ReplaceAll(written, `&`, "&")
	if !readsBack(written) {
		return "", fmt.Errorf("clash: the rule %q cannot be written", rule)
	}
	return written, nil
}

func RulesSummaryForIOS(document string) (*StringBox, error) {
	out, err := withRuleCatalog("RulesSummaryForIOS", document, func(c *RuleCatalog) (*StringBox, error) {
		return WrapString(c.SummaryJSON()), nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func RulesPageForIOS(document string, offset, limit int32, query, target, typesJSON string) (*StringBox, error) {
	out, err := withRuleCatalog("RulesPageForIOS", document, func(c *RuleCatalog) (*StringBox, error) {
		return WrapString(c.PageJSON(offset, limit, query, target, typesJSON)), nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func EditRulesForIOS(document, opsJSON string) (*RuleEdit, error) {
	out, err := recoverAppCall("EditRulesForIOS", func() (*RuleEdit, error) {
		c, err := openRuleCatalog(document)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.edit(opsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func withRuleCatalog(name, document string, f func(*RuleCatalog) (*StringBox, error)) (*StringBox, error) {
	return recoverAppCall(name, func() (*StringBox, error) {
		c, err := openRuleCatalog(document)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return f(c)
	})
}

const maxRuleDocument = 1 << 31

func OpenRuleCatalogForIOSAtPath(path string) (*RuleCatalog, error) {
	out, err := recoverAppCall("OpenRuleCatalogForIOSAtPath", func() (*RuleCatalog, error) { return openRuleCatalogAtPath(path) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func openRuleCatalogAtPath(path string) (*RuleCatalog, error) {
	file, info, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Size() > maxRuleDocument {
		return nil, fmt.Errorf("clash: %s is not a document of at most %d bytes", path, int64(maxRuleDocument))
	}
	var data []byte
	if info.Size() > 0 {
		if data, err = syscall.Mmap(int(file.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED); err != nil {
			return nil, err
		}
	}
	c, err := openRuleCatalog(unsafe.String(unsafe.SliceData(data), len(data)))
	if err != nil {
		if data != nil {
			_ = syscall.Munmap(data)
		}
		return nil, err
	}
	c.mapping = data
	runtime.SetFinalizer(c, func(c *RuleCatalog) { c.Close() })
	return c, nil
}

func RulesSummaryForIOSAtPath(path string) (*StringBox, error) {
	out, err := withRuleCatalogAtPath("RulesSummaryForIOSAtPath", path, func(c *RuleCatalog) (*StringBox, error) {
		return WrapString(c.SummaryJSON()), nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func RulesPageForIOSAtPath(path string, offset, limit int32, query, target, typesJSON string) (*StringBox, error) {
	out, err := withRuleCatalogAtPath("RulesPageForIOSAtPath", path, func(c *RuleCatalog) (*StringBox, error) {
		return WrapString(c.PageJSON(offset, limit, query, target, typesJSON)), nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func withRuleCatalogAtPath(name, path string, f func(*RuleCatalog) (*StringBox, error)) (*StringBox, error) {
	return recoverAppCall(name, func() (*StringBox, error) {
		c, err := openRuleCatalogAtPath(path)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return f(c)
	})
}

func EditRulesForIOSAtPath(source, destination, opsJSON string) (*RuleEdit, error) {
	out, err := recoverAppCall("EditRulesForIOSAtPath", func() (*RuleEdit, error) {
		c, err := openRuleCatalogAtPath(source)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.EditToPath(destination, opsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func (c *RuleCatalog) EditToPath(destination, opsJSON string) (*RuleEdit, error) {
	out, err := recoverAppCall("RuleCatalog.EditToPath", func() (*RuleEdit, error) {
		c.mu.RLock()
		defer c.mu.RUnlock()
		file, err := os.CreateTemp(filepath.Dir(destination), ".rules-edit-")
		if err != nil {
			return nil, err
		}
		defer os.Remove(file.Name())
		out := bufio.NewWriterSize(file, 1<<20)
		first, total, err := c.editTo(opsJSON, out, false)
		if err == nil {
			err = out.Flush()
		}
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, err
		}
		if err := os.Rename(file.Name(), destination); err != nil {
			return nil, err
		}
		return &RuleEdit{FirstChangedIndex: first, Total: total}, nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}
