package clash

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/clashsum"
	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/clashindex"
	"go.yaml.in/yaml/v3"
)

const ruleIndexPrefix, ruleIndexSuffix = "rules-", ".index"

const ruleIndexTemporaryPrefix = ".index-"

const RuleIndexUnavailablePrefix = "x-clash-rule-index: the rule index is not here"

type ruleNames struct {
	targets  map[string]struct{}
	ruleSets map[string]struct{}
	subRules map[string][]constant.Rule
}

var builtInOutbounds = []string{"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL"}

type ruleView struct {
	Rule         []string                  `yaml:"rules"`
	SubRules     map[string][]string       `yaml:"sub-rules"`
	RuleProvider map[string]map[string]any `yaml:"rule-providers"`
}

func ruleViewOf(document *yaml.Node) (ruleView, bool) {
	var view ruleView
	if document == nil || len(document.Content) == 0 {
		return view, true
	}
	if err := document.Decode(&view); err != nil {
		return ruleView{}, false
	}
	return view, true
}

func ruleNamesOf(root map[string]any, view ruleView) ruleNames {
	names := ruleNames{targets: map[string]struct{}{}, ruleSets: map[string]struct{}{}, subRules: map[string][]constant.Rule{}}
	for _, name := range builtInOutbounds {
		names.targets[name] = struct{}{}
	}
	if list, ok := root["proxies"].([]any); ok {
		for _, item := range list {
			if mapping, ok := item.(map[string]any); ok {
				if name, ok := adapter.ClashMappingNodeName(mapping); ok {
					names.targets[name] = struct{}{}
				}
			}
		}
	}
	if groups, ok := root["proxy-groups"].([]any); ok {
		for _, item := range groups {
			if mapping, ok := item.(map[string]any); ok {
				if name, ok := mapping["name"].(string); ok {
					names.targets[name] = struct{}{}
				}
			}
		}
	}
	for name := range view.RuleProvider {
		names.ruleSets[name] = struct{}{}
	}
	for name := range view.SubRules {
		names.subRules[name] = nil
	}
	return names
}

func addLibraryNames(names ruleNames, reference any) {
	mapping, _ := reference.(map[string]any)
	path, _ := mapping["path"].(string)
	want, _ := mapping["sha256"].(string)
	sum, err := hex.DecodeString(want)
	if path == "" || err != nil || len(sum) != sha256.Size {
		return
	}
	library, err := outbound.OpenNodeLibraryFile(path, [sha256.Size]byte(sum))
	if err != nil {
		return
	}
	for i := 0; i < library.Len(); i++ {
		names.targets[library.Name(i)] = struct{}{}
	}
}

func ruleIndexProfile(named string) (runtimeProfile, error) {
	var profile runtimeProfile
	if named != "" {
		var err error
		if profile, err = normalizeRuntimeProfile(named); err != nil {
			return profile, fmt.Errorf("clash: resource map runtimeProfile: %w", err)
		}
	} else {
		setupMu.Lock()
		ready := setupDone
		setupMu.Unlock()
		if !ready {
			return profile, errors.New("clash: a rule index is compiled for its tunnel's runtime profile: name it (runtimeProfile) or call Setup first")
		}
		profile = currentRuntimeProfile()
	}
	if profile == runtimeProfileMacOSApplication {
		profile = runtimeProfileMacOSPacketTunnel
	}
	return profile, nil
}

func (n ruleNames) hasTarget(name string) bool  { _, ok := n.targets[name]; return ok }
func (n ruleNames) hasRuleSet(name string) bool { _, ok := n.ruleSets[name]; return ok }

type ruleLines struct {
	n  int
	at func(i int) string
}

func ruleLinesOf(lines []string) ruleLines {
	return ruleLines{n: len(lines), at: func(i int) string { return lines[i] }}
}

func (l ruleLines) each(skip []int, f func(line string) error) error {
	k := 0
	for i := 0; i < l.n; i++ {
		if k < len(skip) && skip[k] == i {
			k++
			continue
		}
		if err := f(l.at(i)); err != nil {
			return err
		}
	}
	return nil
}

func ruleIndexReference(rm resourceMap, names ruleNames, lines ruleLines, before, after []string) (map[string]any, error) {
	if lines.n == 0 && len(before) == 0 && len(after) == 0 {
		return nil, nil
	}
	directory := rm.RuleIndexDirectory
	profile, err := ruleIndexProfile(rm.RuntimeProfile)
	if err != nil {
		return nil, err
	}
	var removed []int
	removesUID := removesUIDRules(profile)
	if err := checkRulesBefore(before, names, removesUID); err != nil {
		return nil, err
	}
	if removesUID {
		for i := 0; i < lines.n; i++ {
			if ruleCarriesUID(lines.at(i)) {
				removed = append(removed, i)
			}
		}
	}
	if err := checkRulesAfter(after, len(before)+lines.n-len(removed), names, removesUID); err != nil {
		return nil, err
	}
	key := sha256.New()
	io.WriteString(key, nodeLibraryBuilder()+"\x00rules\x00")
	var size [binary.MaxVarintLen64]byte
	_ = lines.each(removed, func(line string) error {
		key.Write(size[:binary.PutUvarint(size[:], uint64(len(line)))])
		io.WriteString(key, line)
		return nil
	})
	source := [sha256.Size]byte(key.Sum(nil))
	path := filepath.Join(directory, ruleIndexPrefix+hex.EncodeToString(source[:16])+ruleIndexSuffix)
	sum, err := usedNodeLibrary(path)
	if err == nil && !ruleIndexAgrees(path, sum, source, names, len(before)) {
		err = errors.New("the index is not these rules', or names what the configuration does not have")
	}
	if err != nil {
		if sum, err = compileRuleIndex(path, source, lines, removed, names, len(before)); err != nil {
			return nil, err
		}
	}
	reference := map[string]any{"path": path, "sha256": hex.EncodeToString(sum)}
	if len(removed) > 0 {
		places := make([]int, len(removed))
		for i, at := range removed {
			places[i] = len(before) + at
		}
		reference["uid-removed"] = places
	}
	if len(before) > 0 {
		reference["prepend"] = anyStrings(before)
	}
	if len(after) > 0 {
		reference["append"] = anyStrings(after)
	}
	return reference, nil
}

func removesUIDRules(profile runtimeProfile) bool {
	policy := runtimePolicyFor(profile, true)
	return policy.networkExtension && (!policy.processMetadata().resolves("UID") || !uidRuleConstructible(runtime.GOOS))
}

func checkRulesBefore(before []string, names ruleNames, removesUID bool) error {
	for i, line := range before {
		if removesUID && ruleCarriesUID(line) {
			return fmt.Errorf("rules[%d] [%s] error: a UID rule cannot go before the configuration's rules here: UID names a socket owner this platform does not expose", i, line)
		}
		if err := config.ClashParseRuleLine(i, line, names.hasTarget, names.hasRuleSet, names.subRules); err != nil {
			return err
		}
	}
	return nil
}

func checkRulesAfter(after []string, first int, names ruleNames, removesUID bool) error {
	for j, line := range after {
		if removesUID && ruleCarriesUID(line) {
			return fmt.Errorf("rules[%d] [%s] error: a UID rule cannot go after the configuration's rules here: UID names a socket owner this platform does not expose", first+j, line)
		}
		if err := config.ClashParseRuleLine(first+j, line, names.hasTarget, names.hasRuleSet, names.subRules); err != nil {
			return err
		}
	}
	return nil
}

func anyStrings(lines []string) []any {
	values := make([]any, len(lines))
	for i, line := range lines {
		values[i] = line
	}
	return values
}

func ruleIndexAgrees(path string, sum []byte, source [sha256.Size]byte, names ruleNames, before int) bool {
	index, err := clashindex.OpenVerified(path, [sha256.Size]byte(sum))
	return err == nil && index.Source() == source && indexParsesHere(index, names, before) == nil
}

func indexParsesHere(index *clashindex.Index, names ruleNames, before int) error {
	var failure error
	index.Targets(func(name string, first int) bool {
		if !names.hasTarget(name) {
			failure = fmt.Errorf("x-clash-rule-index: rule %d names [%s], which the configuration does not have", before+first, name)
		}
		return failure == nil
	})
	if failure != nil {
		return failure
	}
	index.Others(func(i int, line string) bool {
		failure = config.ClashParseRuleLine(before+i, line, names.hasTarget, names.hasRuleSet, names.subRules)
		return failure == nil
	})
	return failure
}

func compileRuleIndex(path string, source [sha256.Size]byte, lines ruleLines, removed []int, names ruleNames, before int) ([]byte, error) {
	compiler := config.NewClashRuleIndexCompiler(names.hasTarget, names.hasRuleSet, names.subRules)
	compiler.SetSource(source)
	compiler.SetFirstPlace(before)
	if err := lines.each(removed, compiler.Add); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	nodeLibraryFilesMu.Lock()
	defer nodeLibraryFilesMu.Unlock()
	file, err := os.CreateTemp(filepath.Dir(path), ruleIndexTemporaryPrefix)
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	out := bufio.NewWriterSize(file, 1<<20)
	_, sum, err := compiler.Write(out)
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
		return nil, fmt.Errorf("rule index: %w", err)
	}
	if _, err := clashindex.OpenVerified(file.Name(), sum); err != nil {
		return nil, fmt.Errorf("rule index: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return nil, fmt.Errorf("rule index: %w", err)
	}
	clashsum.ProveWritten(path, sum)
	return sum[:], nil
}

func publishedRuleIndexHere(reference any, names ruleNames, viewed bool, rm resourceMap, before, after []string) (any, error) {
	mapping, _ := reference.(map[string]any)
	path, _ := mapping["path"].(string)
	want, _ := mapping["sha256"].(string)
	if path == "" || want == "" {
		return nil, errors.New("x-clash-rule-index: a path and a SHA-256 are required")
	}
	gone := errors.New("x-clash-rule-index: this is a published configuration whose rule index is not here; publish its source instead")
	sum, err := usedNodeLibrary(path)
	if err != nil || hex.EncodeToString(sum) != strings.ToLower(want) {
		return nil, gone
	}
	index, err := clashindex.OpenVerified(path, [sha256.Size]byte(sum))
	if err != nil {
		return nil, gone
	}
	if !viewed {
		return reference, nil
	}
	carried, err := carriedRules(mapping, "prepend")
	if err != nil {
		return nil, err
	}
	carriedAfter, err := carriedRules(mapping, "append")
	if err != nil {
		return nil, err
	}
	removesUID := false
	if (before != nil && len(before) > 0) || (after != nil && len(after) > 0) {
		profile, err := ruleIndexProfile(rm.RuntimeProfile)
		if err != nil {
			return nil, err
		}
		removesUID = removesUIDRules(profile)
	}
	removesUIDBefore, removesUIDAfter := removesUID && before != nil, removesUID && after != nil
	if before == nil {
		before = carried
	}
	if after == nil {
		after = carriedAfter
	}
	if err := checkRulesBefore(before, names, removesUIDBefore); err != nil {
		return nil, err
	}
	if err := indexParsesHere(index, names, len(before)); err != nil {
		return nil, fmt.Errorf("%w; publish its source instead", err)
	}
	if err := checkRulesAfter(after, len(before)+index.Len(), names, removesUIDAfter); err != nil {
		return nil, err
	}
	published := make(map[string]any, len(mapping))
	for key, value := range mapping {
		published[key] = value
	}
	delete(published, "prepend")
	if len(before) > 0 {
		published["prepend"] = anyStrings(before)
	}
	delete(published, "append")
	if len(after) > 0 {
		published["append"] = anyStrings(after)
	}
	if places, ok := mapping["uid-removed"].([]any); ok && len(before) != len(carried) {
		moved := make([]any, len(places))
		for i, place := range places {
			if at, isInt := place.(int); isInt {
				moved[i] = at - len(carried) + len(before)
			} else {
				moved[i] = place
			}
		}
		published["uid-removed"] = moved
	}
	return published, nil
}

func carriedRulesBefore(mapping map[string]any) ([]string, error) {
	return carriedRules(mapping, "prepend")
}

func carriedRules(mapping map[string]any, key string) ([]string, error) {
	value, carried := mapping[key]
	if !carried || value == nil {
		return nil, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("x-clash-rule-index: %s is a list of rules", key)
	}
	lines := make([]string, len(list))
	for i, entry := range list {
		line, isString := entry.(string)
		if !isString {
			return nil, fmt.Errorf("x-clash-rule-index: %s[%d] is not a rule", key, i)
		}
		lines[i] = line
	}
	return lines, nil
}

func PruneRuleIndexes(directory, keep string) error {
	_, err := recoverAppCall("PruneRuleIndexes", func() (struct{}, error) {
		var keeps []string
		if keep != "" {
			keeps = append(keeps, keep)
		}
		return struct{}{}, pruneFiles(directory, keeps, isRuleIndexFile)
	})
	return bridgeSafeError(err)
}

func PruneRuleIndexesKeeping(directory, keepJSON string) error {
	_, err := recoverAppCall("PruneRuleIndexesKeeping", func() (struct{}, error) {
		var keeps []string
		if strings.TrimSpace(keepJSON) != "" {
			if err := json.Unmarshal([]byte(keepJSON), &keeps); err != nil {
				return struct{}{}, fmt.Errorf("clash: indexes to keep: %w", err)
			}
		}
		return struct{}{}, pruneFiles(directory, keeps, isRuleIndexFile)
	})
	return bridgeSafeError(err)
}

func isRuleIndexFile(name string) bool {
	return strings.HasPrefix(name, ruleIndexTemporaryPrefix) ||
		strings.HasPrefix(name, ruleIndexPrefix) && strings.HasSuffix(name, ruleIndexSuffix)
}

func rawRuleIndex(raw *config.RawConfig) *clashindex.Index {
	if raw == nil {
		return nil
	}
	index, err := config.ClashOpenRuleIndex(raw.ClashRuleIndex)
	if err != nil {
		return nil
	}
	return index
}

func rawRuleIndexChecked(raw *config.RawConfig) (*clashindex.Index, error) {
	if raw == nil || len(raw.Rule) > 0 || rawRulesElsewhere(raw) {
		return nil, nil
	}
	return config.ClashOpenRuleIndex(raw.ClashRuleIndex)
}

func documentRuleIndexError(root map[string]any) error {
	if rules, _ := root["rules"].([]any); len(rules) > 0 {
		return nil
	}
	ref, named := documentRuleIndexRef(root)
	if !named {
		return nil
	}
	_, err := config.ClashOpenRuleIndex(ref)
	return err
}

func rawRulesElsewhere(raw *config.RawConfig) bool {
	return raw != nil && len(raw.Rule) == 0 && raw.ClashRules != nil && raw.ClashRules.Len() > 0
}

type catalogRules struct{ catalog *RuleCatalog }

func (r catalogRules) Len() int        { return len(r.catalog.items) }
func (r catalogRules) At(i int) string { return r.catalog.value(i) }

func eachRuleLine(raw *config.RawConfig, f func(index int, line string)) {
	eachRuleLineOf(raw, rawRuleIndex(raw), f)
}

func eachRuleLineOf(raw *config.RawConfig, index *clashindex.Index, f func(index int, line string)) {
	if rawRulesElsewhere(raw) {
		for i, n := 0, raw.ClashRules.Len(); i < n; i++ {
			f(i, raw.ClashRules.At(i))
		}
		return
	}
	if index != nil && len(raw.Rule) == 0 {
		before := raw.ClashRuleIndex.Prepend
		for i, line := range before {
			f(i, line)
		}
		index.Others(func(i int, line string) bool { f(len(before)+i, line); return true })
		first := len(before) + index.Len()
		for j, line := range raw.ClashRuleIndex.Append {
			f(first+j, line)
		}
		return
	}
	for i, line := range raw.Rule {
		f(i, line)
	}
}

func ruleCountOf(raw *config.RawConfig) int {
	return ruleCountOfIndex(raw, rawRuleIndex(raw))
}

func ruleCountOfIndex(raw *config.RawConfig, index *clashindex.Index) int {
	if rawRulesElsewhere(raw) {
		return raw.ClashRules.Len()
	}
	if index != nil && len(raw.Rule) == 0 {
		return len(raw.ClashRuleIndex.Prepend) + index.Len() + len(raw.ClashRuleIndex.UIDRemoved) + len(raw.ClashRuleIndex.Append)
	}
	return len(raw.Rule)
}

func eachDocumentRuleLine(root map[string]any, f func(index int, line string)) {
	if rules, ok := root["rules"].([]any); ok && len(rules) > 0 {
		for i, entry := range rules {
			if text, isString := entry.(string); isString {
				f(i, text)
			}
		}
		return
	}
	ref, _ := documentRuleIndexRef(root)
	if index := documentRuleIndex(root); index != nil {
		before := len(ref.Prepend)
		for i, line := range ref.Prepend {
			f(i, line)
		}
		index.Others(func(i int, line string) bool { f(writtenPlace(before+i, ref.UIDRemoved), line); return true })
		first := before + index.Len()
		for j, line := range ref.Append {
			f(writtenPlace(first+j, ref.UIDRemoved), line)
		}
	}
}

func writtenPlace(i int, removed []int) int {
	for _, at := range removed {
		if at > i {
			break
		}
		i++
	}
	return i
}

func documentRuleIndex(root map[string]any) *clashindex.Index {
	ref, ok := documentRuleIndexRef(root)
	if !ok {
		return nil
	}
	index, err := config.ClashOpenRuleIndex(ref)
	if err != nil {
		return nil
	}
	return index
}

func documentRuleIndexRef(root map[string]any) (config.ClashRuleIndexRef, bool) {
	mapping, _ := root["x-clash-rule-index"].(map[string]any)
	if generic, ok := root["x-clash-rule-index"].(map[any]any); ok {
		mapping = make(map[string]any, len(generic))
		for key, value := range generic {
			if name, isString := key.(string); isString {
				mapping[name] = value
			}
		}
	}
	if mapping == nil {
		return config.ClashRuleIndexRef{}, false
	}
	var ref config.ClashRuleIndexRef
	ref.Path, _ = mapping["path"].(string)
	ref.SHA256, _ = mapping["sha256"].(string)
	if places, ok := mapping["uid-removed"].([]any); ok {
		for _, place := range places {
			if at, ok := place.(int); ok {
				ref.UIDRemoved = append(ref.UIDRemoved, at)
			}
		}
	}
	ref.Prepend, _ = carriedRulesBefore(mapping)
	ref.Append, _ = carriedRules(mapping, "append")
	return ref, true
}

func indexedRuleLinesIn(content string, document *yaml.Node) string {
	if !strings.Contains(content, "x-clash-rule-index") {
		return ""
	}
	var head struct {
		Index any   `yaml:"x-clash-rule-index"`
		Rules []any `yaml:"rules"`
	}
	var err error
	if document != nil && len(document.Content) > 0 {
		err = document.Decode(&head)
	} else {
		err = yaml.Unmarshal([]byte(content), &head)
	}
	if err != nil || head.Index == nil || len(head.Rules) > 0 {
		return ""
	}
	var lines strings.Builder
	eachDocumentRuleLine(map[string]any{"x-clash-rule-index": head.Index}, func(_ int, line string) {
		lines.WriteString(line)
		lines.WriteByte('\n')
	})
	return lines.String()
}
