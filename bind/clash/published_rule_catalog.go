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
	before     []string
	after      []string
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
	return &PublishedRuleCatalog{index: index, before: published.Index.Prepend, after: published.Index.Append, uidRemoved: len(published.Index.UIDRemoved)}, nil
}

func (c *PublishedRuleCatalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.index, c.before, c.after = nil, nil, nil
}

func (c *PublishedRuleCatalog) count() int {
	if c.index == nil {
		return 0
	}
	return len(c.before) + c.index.Len() + len(c.after)
}

func (c *PublishedRuleCatalog) firstAfter() int { return len(c.before) + c.index.Len() }

func (c *PublishedRuleCatalog) line(i int) string {
	if i < len(c.before) {
		return c.before[i]
	}
	if first := c.firstAfter(); i >= first {
		return c.after[i-first]
	}
	line, _, _ := c.index.Written(i - len(c.before))
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
	return int32(len(c.before))
}

func (c *PublishedRuleCatalog) Appended() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.index == nil {
		return 0
	}
	return int32(len(c.after))
}

func (c *PublishedRuleCatalog) rule(i int) (tp, target, payload string, mapped bool) {
	if i >= len(c.before) && i < c.firstAfter() {
		if tp, target, ok := c.index.MappedTypeAndTarget(i - len(c.before)); ok {
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
		prepended, appended = len(c.before), len(c.after)
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
