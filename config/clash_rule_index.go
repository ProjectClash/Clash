package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/clashindex"
	RC "github.com/ProjectClash/Clash/rules/common"
	"github.com/ProjectClash/Clash/rules/logic"
	RW "github.com/ProjectClash/Clash/rules/wrapper"
)

type ClashRuleIndexRef struct {
	Path   string `yaml:"path" json:"path"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	UIDRemoved []int `yaml:"uid-removed,omitempty" json:"uid-removed,omitempty"`
	Prepend []string `yaml:"prepend,omitempty" json:"prepend,omitempty"`
	Append []string `yaml:"append,omitempty" json:"append,omitempty"`
}

type ClashRuleSource interface {
	Len() int
	At(i int) string
}

func ClashOpenRuleIndex(ref ClashRuleIndexRef) (*clashindex.Index, error) {
	if ref.Path == "" && ref.SHA256 == "" {
		return nil, nil
	}
	sum, err := hex.DecodeString(ref.SHA256)
	if err != nil || len(sum) != sha256.Size || ref.Path == "" {
		return nil, errors.New("x-clash-rule-index: a path and a SHA-256 are required")
	}
	open := clashindex.OpenVerified
	if ClashRuleIndexesVerified.Load() {
		open = clashindex.Open
	}
	index, err := open(ref.Path, [sha256.Size]byte(sum))
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrRuleIndexUnavailable, err)
	}
	return index, nil
}

var ClashRuleIndexesVerified atomic.Bool

var ErrRuleIndexUnavailable = errors.New("x-clash-rule-index: the rule index is not here; publish the configuration again")

func clashRuleIndexTable(cfg *RawConfig, proxies map[string]C.Proxy, library C.ProxyLibrary, ruleProviders map[string]P.RuleProvider, subRules map[string][]C.Rule) (C.RuleTable, error) {
	ref := cfg.ClashRuleIndex
	if ref.Path == "" && ref.SHA256 == "" {
		return nil, nil
	}
	if len(cfg.Rule) > 0 {
		return nil, errors.New("x-clash-rule-index: a configuration whose rules are in an index writes none in rules")
	}
	index, err := ClashOpenRuleIndex(ref)
	if err != nil {
		return nil, err
	}
	hasTarget := func(name string) bool { return hasProxy(proxies, library, name) }
	hasRuleSet := func(name string) bool { _, ok := ruleProviders[name]; return ok }
	before := make(C.RuleList, 0, len(ref.Prepend))
	for i, line := range ref.Prepend {
		rule, err := parseRuleLine(i, line, hasTarget, hasRuleSet, subRules, "rules")
		if err != nil {
			return nil, err
		}
		before = append(before, rule)
	}
	k := len(before)
	var missing error
	index.Targets(func(name string, first int) bool {
		if !hasTarget(name) {
			missing = fmt.Errorf("%w (rule %d names [%s], which the configuration does not have)", ErrRuleIndexUnavailable, k+first, name)
			return false
		}
		return true
	})
	if missing != nil {
		return nil, missing
	}
	others := make([]C.Rule, 0, index.OtherCount())
	var parseErr error
	index.Others(func(i int, line string) bool {
		rule, err := parseRuleLine(k+i, line, hasTarget, hasRuleSet, subRules, "rules")
		if err != nil {
			parseErr = err
			return false
		}
		others = append(others, rule)
		return true
	})
	if parseErr != nil {
		return nil, parseErr
	}
	table, err := index.Table(others)
	if err != nil {
		return nil, err
	}
	first := k + table.Len()
	after := make(C.RuleList, 0, len(ref.Append))
	for j, line := range ref.Append {
		rule, err := parseRuleLine(first+j, line, hasTarget, hasRuleSet, subRules, "rules")
		if err != nil {
			return nil, err
		}
		after = append(after, rule)
	}
	return C.ClashWithRulesAround(before, ref.Prepend, table, after, ref.Append), nil
}

type ClashRuleIndexCompiler struct {
	first      int
	compiler   *clashindex.Compiler
	hasTarget  func(string) bool
	hasRuleSet func(string) bool
	subRules   map[string][]C.Rule
}

func NewClashRuleIndexCompiler(hasTarget, hasRuleSet func(string) bool, subRules map[string][]C.Rule) *ClashRuleIndexCompiler {
	return &ClashRuleIndexCompiler{compiler: clashindex.NewCompiler(), hasTarget: hasTarget, hasRuleSet: hasRuleSet, subRules: subRules}
}

func (c *ClashRuleIndexCompiler) SetFirstPlace(first int) { c.first = first }

func (c *ClashRuleIndexCompiler) Add(line string) error {
	index := c.first + c.compiler.Len()
	rule, readsGeodata, err := parseRuleLineWithoutGeodata(index, line, c.hasTarget, c.hasRuleSet, c.subRules)
	if err != nil {
		return err
	}
	if _, notifies := rule.(*RW.NotifyingRule); readsGeodata || notifies {
		return c.compiler.AddLine(line)
	}
	return c.compiler.Add(line, rule)
}

func parseRuleLineWithoutGeodata(idx int, line string, hasTarget, hasRuleSet func(string) bool, subRules map[string][]C.Rule) (C.Rule, bool, error) {
	readsGeodata := false
	var parse RC.ParseRuleFunc
	parse = func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
		if tp != "MATCH" && payload == "" {
			return nil, fmt.Errorf("missing subsequent parameters: %s", tp)
		}
		switch tp {
		case "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN":
			readsGeodata = true
			return &geodataStandIn{tp: tp, payload: payload, adapter: target}, nil
		case "SUB-RULE":
			return logic.NewSubRule(payload, target, subRules, parse)
		case "AND":
			return logic.NewAND(payload, target, parse)
		case "OR":
			return logic.NewOR(payload, target, parse)
		case "NOT":
			return logic.NewNOT(payload, target, parse)
		}
		return R.ParseRule(tp, payload, target, params, subRules)
	}
	rule, err := parseRuleLineWith(idx, line, hasTarget, hasRuleSet, subRules, "rules", parse)
	return rule, readsGeodata, err
}

type geodataStandIn struct {
	RC.Base
	tp, payload, adapter string
}

func (g *geodataStandIn) RuleType() C.RuleType {
	switch g.tp {
	case "GEOSITE":
		return C.GEOSITE
	case "IP-ASN":
		return C.IPASN
	case "SRC-IP-ASN":
		return C.SrcIPASN
	case "SRC-GEOIP":
		return C.SrcGEOIP
	}
	return C.GEOIP
}
func (g *geodataStandIn) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) { return false, "" }
func (g *geodataStandIn) Adapter() string                                     { return g.adapter }
func (g *geodataStandIn) Payload() string                                     { return g.payload }

func (c *ClashRuleIndexCompiler) SetSource(source [sha256.Size]byte) { c.compiler.SetSource(source) }

func (c *ClashRuleIndexCompiler) Len() int { return c.compiler.Len() }

func (c *ClashRuleIndexCompiler) Write(w io.Writer) (int64, [sha256.Size]byte, error) {
	return c.compiler.Write(w)
}

func ClashParseRuleLine(idx int, line string, hasTarget, hasRuleSet func(string) bool, subRules map[string][]C.Rule) error {
	_, _, err := parseRuleLineWithoutGeodata(idx, line, hasTarget, hasRuleSet, subRules)
	return err
}
