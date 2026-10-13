package provider

import (
	"errors"
	"fmt"
	"hash/maphash"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ProjectClash/Clash/component/cidr"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/rules/common"
)

type classicalStrategy struct {
	names  []classicalName
	others []classicalRule
	count  int
	parse  common.ParseRuleFunc

	keepText bool
	indexDirectory string
	mapped *classicalMapped

	indexed bool
	seed     maphash.Seed
	domains  classicalNameTable
	suffixes classicalNameTable
	steps    []classicalStep

	keywords, regexes, children int
	heavy                       error
}

type classicalNameTable struct {
	slots []int32
	mask  uint64
}

func newClassicalNameTable(names []classicalName, suffix bool, seed maphash.Seed) classicalNameTable {
	n := 0
	for _, name := range names {
		if name.suffix == suffix {
			n++
		}
	}
	if n == 0 {
		return classicalNameTable{}
	}
	size := 8
	for size < n+n/4 {
		size <<= 1
	}
	table := classicalNameTable{slots: make([]int32, size), mask: uint64(size - 1)}
	for i, name := range names {
		if name.suffix != suffix {
			continue
		}
		for h := maphash.String(seed, name.name) & table.mask; ; h = (h + 1) & table.mask {
			slot := table.slots[h]
			if slot == 0 {
				table.slots[h] = int32(i + 1)
				break
			}
			if names[slot-1].name == name.name {
				break
			}
		}
	}
	return table
}

func (t classicalNameTable) find(names []classicalName, name string, seed maphash.Seed) (int32, bool) {
	if len(t.slots) == 0 {
		return 0, false
	}
	for h := maphash.String(seed, name) & t.mask; ; h = (h + 1) & t.mask {
		slot := t.slots[h]
		if slot == 0 {
			return 0, false
		}
		if names[slot-1].name == name {
			return names[slot-1].line, true
		}
	}
}

type classicalName struct {
	name   string
	line   int32
	suffix bool
}

type classicalRule struct {
	rule C.Rule
	line int32
	text string
}

type classicalStep struct {
	line    int
	rule    C.Rule
	cidrs   *cidr.IpCidrSet
	source  bool
	resolve bool
	mapped *cidr.MappedIpCidrSet
}

func (c *classicalStrategy) Behavior() P.RuleBehavior {
	return P.Classical
}

func (c *classicalStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	if !c.indexed {
		host := metadata.RuleHost()
		n := 0
		for _, other := range c.others {
			for ; n < len(c.names) && c.names[n].line < other.line; n++ {
				if c.names[n].matches(host) {
					return true
				}
			}
			if m, _ := other.rule.Match(metadata, helper); m {
				return true
			}
		}
		for ; n < len(c.names); n++ {
			if c.names[n].matches(host) {
				return true
			}
		}
		return false
	}
	domainLine, domainMatched := c.firstDomainLine(metadata.RuleHost())
	for i := range c.steps {
		step := &c.steps[i]
		if domainMatched && step.line > domainLine {
			return true
		}
		if step.rule != nil {
			if m, _ := step.rule.Match(metadata, helper); m {
				return true
			}
			continue
		}
		if step.resolve && helper.ResolveIP != nil {
			helper.ResolveIP()
		}
		ip := metadata.DstIP
		if step.source {
			ip = metadata.SrcIP
		}
		if ip.IsValid() && ((step.cidrs != nil && step.cidrs.IsContain(ip)) || (step.mapped != nil && step.mapped.MatchIp(ip))) {
			return true
		}
	}
	return domainMatched
}

func (n classicalName) matches(host string) bool {
	if !n.suffix {
		return host == n.name
	}
	return host == n.name || strings.HasSuffix(host, "."+n.name)
}

func (c *classicalStrategy) firstDomainLine(host string) (int, bool) {
	first, found := 0, false
	consider := func(line int32, ok bool) {
		if ok && (!found || int(line) < first) {
			first, found = int(line), true
		}
	}
	if m := c.mapped; m != nil {
		consider(m.find(host, false))
		if len(m.suffixes) == 0 {
			return first, found
		}
		consider(m.find(host, true))
		for i := 0; i < len(host); i++ {
			if host[i] == '.' {
				consider(m.find(host[i+1:], true))
			}
		}
		return first, found
	}
	consider(c.domains.find(c.names, host, c.seed))
	if len(c.suffixes.slots) == 0 {
		return first, found
	}
	consider(c.suffixes.find(c.names, host, c.seed))
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			consider(c.suffixes.find(c.names, host[i+1:], c.seed))
		}
	}
	return first, found
}

func (c *classicalStrategy) Count() int {
	return c.count
}

func (c *classicalStrategy) Reset() {
	c.names, c.others, c.mapped = nil, nil, nil
	c.count = 0
	c.keywords, c.regexes, c.children, c.heavy = 0, 0, 0, nil
	c.indexed = false
	c.domains, c.suffixes, c.steps = classicalNameTable{}, classicalNameTable{}, nil
}

func (c *classicalStrategy) Insert(rule string) {
	if c.heavy != nil {
		return
	}
	if c.mapped != nil {
		log.Warnln("classical rule [%s] follows a compiled index; ignored", rule)
		return
	}
	if c.indexDirectory != "" && !c.indexed && c.count == 0 && strings.HasPrefix(rule, ClashClassicalIndexStubType+",") {
		if index, checksum, source, format, ok := parseClassicalIndexStub(rule, c.indexDirectory); ok {
			c.loadCompiled(index, checksum, source, format)
			return
		}
	}
	tp, payload, target, params := common.ParseRulePayload(rule, false)
	if c.heavy = c.countHeavy(tp, payload); c.heavy != nil {
		log.Errorln("[Rule] %v", c.heavy)
		c.names, c.others, c.count = nil, nil, 0
		return
	}
	if (tp == "DOMAIN" || tp == "DOMAIN-SUFFIX") && payload != "" && !c.indexed {
		c.names = append(c.names, classicalName{name: strings.ToLower(payload), line: int32(c.count), suffix: tp == "DOMAIN-SUFFIX"})
		c.count++
		return
	}
	r, err := c.payloadToRule(tp, payload, target, params)
	if err != nil && c.keepText {
		c.others = append(c.others, classicalRule{line: int32(c.count), text: rule})
	} else if err != nil {
		log.Warnln("parse classical rule [%s] error: %s", rule, err.Error())
	} else if c.indexed {
		log.Warnln("classical rule [%s] inserted after the set was built; ignored", rule)
	} else {
		other := classicalRule{rule: r, line: int32(c.count)}
		if c.keepText {
			other.text = rule
		}
		c.others = append(c.others, other)
		c.count++
	}
}

func (c *classicalStrategy) payloadToRule(tp, payload, target string, params []string) (C.Rule, error) {
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type on classical rule-set: %s", tp)
	}
	return c.parse(tp, payload, target, params, nil)
}

func (c *classicalStrategy) FinishInsert() {
	if c.indexed {
		return
	}
	seed := maphash.MakeSeed()
	domains := newClassicalNameTable(c.names, false, seed)
	suffixes := newClassicalNameTable(c.names, true, seed)
	steps, ok := buildClassicalSteps(c.others)
	if !ok {
		return
	}
	c.seed, c.domains, c.suffixes, c.steps = seed, domains, suffixes, steps
	c.indexed = true
	c.others = nil
}

func NewClassicalStrategy(parse common.ParseRuleFunc) *classicalStrategy {
	return &classicalStrategy{parse: parse}
}

func buildClassicalSteps(others []classicalRule) ([]classicalStep, bool) {
	steps := make([]classicalStep, 0, len(others))
	for _, other := range others {
		position, rule := int(other.line), other.rule
		if r, ok := rule.(*common.IPCIDR); ok {
			if prefix, err := netip.ParsePrefix(r.Payload()); err == nil {
				source, resolve := r.ClashIsSourceIP(), r.ClashResolvesIP()
				if n := len(steps); n > 0 && steps[n-1].cidrs != nil &&
					steps[n-1].source == source && steps[n-1].resolve == resolve {
					if steps[n-1].cidrs.AddIpCidr(prefix) == nil {
						continue
					}
				} else if set := cidr.NewIpCidrSet(); set.AddIpCidr(prefix) == nil {
					steps = append(steps, classicalStep{line: position, cidrs: set, source: source, resolve: resolve})
					continue
				}
			}
		}
		steps = append(steps, classicalStep{line: position, rule: rule})
	}
	if len(steps) < cap(steps) {
		steps = append(make([]classicalStep, 0, len(steps)), steps...)
	}
	for i := range steps {
		if steps[i].cidrs != nil {
			if err := steps[i].cidrs.Merge(); err != nil {
				log.Warnln("index classical rule-set: %s", err.Error())
				return nil, false
			}
		}
	}
	return steps, true
}

func (c *classicalStrategy) loadCompiled(index string, checksum uint32, source string, format P.RuleFormat) {
	m, names, others, ipSteps, err := loadClassicalIndex(index, checksum)
	if err == nil && len(others) > ClashClassicalOthersLimit {
		err = fmt.Errorf("%d lines parsed at load, more than %d", len(others), ClashClassicalOthersLimit)
	}
	if err == nil {
		rulesOf := make([]classicalRule, 0, len(others))
		for _, other := range others {
			tp, payload, target, params := common.ParseRulePayload(other.text, false)
			heavy := c.countHeavy(tp, payload)
			if heavy == nil && len(others)+c.children > ClashClassicalOthersLimit {
				heavy = fmt.Errorf("%w: more than %d rules parsed at load, counting the rules inside logic rules, so it loads no rules", ErrClassicalTooHeavy, ClashClassicalOthersLimit)
			}
			if heavy != nil {
				log.Errorln("[Rule] %v", heavy)
				c.names, c.others, c.count, c.keywords, c.regexes, c.children = nil, nil, 0, 0, 0, 0
				return
			}
			r, parseErr := c.payloadToRule(tp, payload, target, params)
			if parseErr != nil {
				log.Warnln("parse classical rule [%s] error: %s", other.text, parseErr.Error())
				continue
			}
			rulesOf = append(rulesOf, classicalRule{rule: r, line: other.line})
		}
		if steps, ok := buildClassicalSteps(rulesOf); ok {
			ipRules := 0
			for _, step := range ipSteps {
				ipRules += step.rules
				steps = append(steps, classicalStep{line: step.line, mapped: step.set, source: step.source, resolve: step.resolve})
			}
			sort.SliceStable(steps, func(i, j int) bool { return steps[i].line < steps[j].line })
			c.mapped, c.count, c.steps, c.indexed = m, names+len(rulesOf)+ipRules, steps, true
			return
		}
		err = errors.New("its IP lines do not merge")
	}
	log.Warnln("[Rule] compiled classical index %s unusable (%v); reading its source", index, err)
	if info, statErr := os.Lstat(source); statErr == nil && info.Size() > ClashClassicalSourceFallbackLimit {
		log.Errorln("[Rule] classical source %s: %d bytes, past the %d read without an index; publish the configuration again", source, info.Size(), ClashClassicalSourceFallbackLimit)
		return
	}
	payload, readErr := readRegularFile(source)
	if readErr != nil {
		log.Errorln("[Rule] classical source %s: %v", source, readErr)
		return
	}
	lines, parseErr := ClashClassicalLines(payload, format)
	if parseErr != nil {
		log.Errorln("[Rule] classical source %s: %v", source, parseErr)
		return
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, ClashClassicalIndexStubType+",") {
			c.Insert(line)
		}
	}
}

var ClashClassicalSourceFallbackLimit int64 = 1 << 20

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.ReadFile(path)
}

const (
	ClashClassicalKeywordLimit = 20000
	ClashClassicalRegexLimit   = 1000
)

const (
	ClashClassicalOthersLimit = 20000
	ClashClassicalIPRunLimit  = 20000
)

var clashLogicChildType = regexp.MustCompile(`\(\s*([^,()\s]+)\s*,`)

var ErrClassicalTooHeavy = errors.New("rule set too heavy for iOS")

func (c *classicalStrategy) countHeavy(tp, payload string) error {
	switch strings.ToUpper(strings.TrimSpace(tp)) {
	case "AND", "OR", "NOT":
		for _, match := range clashLogicChildType.FindAllStringSubmatch(payload, -1) {
			c.children++
			if c.children > ClashClassicalOthersLimit {
				return fmt.Errorf("%w: more than %d rules inside logic rules in one set, so it loads no rules", ErrClassicalTooHeavy, ClashClassicalOthersLimit)
			}
			if err := c.countHeavy(strings.ToUpper(match[1]), ""); err != nil {
				return err
			}
		}
		return nil
	}
	switch tp {
	case "DOMAIN-KEYWORD":
		c.keywords++
		if c.keywords > ClashClassicalKeywordLimit {
			return fmt.Errorf("%w: more than %d DOMAIN-KEYWORD rules in one set, so it loads no rules", ErrClassicalTooHeavy, ClashClassicalKeywordLimit)
		}
	case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		c.regexes++
		if c.regexes > ClashClassicalRegexLimit {
			return fmt.Errorf("%w: more than %d regular-expression rules in one set, so it loads no rules", ErrClassicalTooHeavy, ClashClassicalRegexLimit)
		}
	}
	return nil
}
