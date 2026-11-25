package clash

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/rules/clashindex"
	"go.yaml.in/yaml/v3"
)

var ErrNoPublishedRuleIndex = errors.New("clash: this configuration writes its rules and names no rule index")

type PublishedRuleCatalog struct {
	mu         sync.RWMutex
	index      *clashindex.Index
	before     config.ClashRulesAround
	after      config.ClashRulesAround
	uidRemoved int
}

func OpenRuleCatalogForPublishedAtPath(path string) (*PublishedRuleCatalog, error) {
	out, err := recoverAppCall("OpenRuleCatalogForPublishedAtPath", func() (*PublishedRuleCatalog, error) { return openPublishedRuleCatalog(path) })
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func openPublishedRuleCatalog(path string) (*PublishedRuleCatalog, error) {
	file, _, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	text, err := io.ReadAll(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	var published struct {
		Index *config.ClashRuleIndexRef `yaml:"x-clash-rule-index"`
		Rules yaml.Node                 `yaml:"rules"`
	}
	if err := yaml.Unmarshal(text, &published); err != nil {
		return nil, fmt.Errorf("clash: the published configuration does not read: %w", err)
	}
	if published.Index == nil {
		if published.Rules.Kind == yaml.SequenceNode && len(published.Rules.Content) > 0 {
			return nil, ErrNoPublishedRuleIndex
		}
		return &PublishedRuleCatalog{}, nil
	}
	index, err := config.ClashOpenRuleIndex(*published.Index)
	if err != nil {
		return nil, err
	}
	before, err := published.Index.ClashRulesBefore()
	if err != nil {
		return nil, err
	}
	after, err := published.Index.ClashRulesAfter()
	if err != nil {
		return nil, err
	}
	return &PublishedRuleCatalog{index: index, before: before, after: after, uidRemoved: len(published.Index.UIDRemoved)}, nil
}

func (c *PublishedRuleCatalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index, c.before, c.after = nil, config.ClashRulesAround{}, config.ClashRulesAround{}
}

func (c *PublishedRuleCatalog) count() int {
	if c.index == nil {
		return 0
	}
	return c.before.Len() + c.index.Len() + c.after.Len()
}

func (c *PublishedRuleCatalog) firstAfter() int { return c.before.Len() + c.index.Len() }

func (c *PublishedRuleCatalog) line(i int) string {
	if i < c.before.Len() {
		line, _ := c.before.Line(i)
		return line
	}
	if first := c.firstAfter(); i >= first {
		line, _ := c.after.Line(i - first)
		return line
	}
	line, _, _ := c.index.Written(i - c.before.Len())
	return line
}

func (c *PublishedRuleCatalog) Total() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int32(c.count())
}

func (c *PublishedRuleCatalog) UIDRemoved() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int32(c.uidRemoved)
}

func (c *PublishedRuleCatalog) Prepended() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.index == nil {
		return 0
	}
	return int32(c.before.Len())
}

func (c *PublishedRuleCatalog) Appended() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.index == nil {
		return 0
	}
	return int32(c.after.Len())
}

func (c *PublishedRuleCatalog) rule(i int) (tp, target, payload string, mapped bool) {
	index, j := c.index, i-c.before.Len()
	if i < c.before.Len() {
		index, j = c.before.Index, i
	} else if first := c.firstAfter(); i >= first {
		index, j = c.after.Index, i-first
	}
	if index != nil {
		if tp, target, ok := index.MappedTypeAndTarget(j); ok {
			return tp, target, "", true
		}
	}
	tp, target, _, payload = ruleTypeAndTarget(c.line(i))
	return tp, target, payload, false
}

func (c *PublishedRuleCatalog) SummaryJSON() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	prepended, appended := 0, 0
	if c.index != nil {
		prepended, appended = c.before.Len(), c.after.Len()
	}
	return bridgeSafeString(summarizeRulesBefore(c.count(), c.uidRemoved, prepended, appended, c.rule))
}

func (c *PublishedRuleCatalog) PageJSON(offset, limit int32, query, target, typesJSON string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	filter, err := parseRuleFilter(query, target, typesJSON)
	return bridgeSafeString(pageRules(c.count(), offset, limit, filter, err, func(i int) bool {
		if filter.folded == "" {
			tp, ruleTarget, _, _ := c.rule(i)
			return filter.keepsKind(tp, ruleTarget)
		}
		line := c.line(i)
		if !containsFolded(line, filter.folded) {
			return false
		}
		tp, ruleTarget, _, _ := ruleTypeAndTarget(line)
		return filter.keepsKind(tp, ruleTarget)
	}, func(i int) rulePageEntry {
		line := c.line(i)
		tp, ruleTarget, _, _ := ruleTypeAndTarget(line)
		return rulePageEntry{Index: i, Text: line, Rule: line, Type: tp, Target: ruleTarget}
	}))
}
