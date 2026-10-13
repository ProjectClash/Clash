package provider

import (
	"errors"
	"io"
	"runtime"
	"strings"

	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"

	"golang.org/x/exp/slices"
)

type domainStrategy struct {
	count            int
	domainSetBuilder trie.DomainSetBuilder
	domainSet        *trie.DomainSet
	stubDirectory string
	stubbed       bool
	mapped        *mappedDomainSet
}

func (d *domainStrategy) Behavior() P.RuleBehavior {
	return P.Domain
}

func (d *domainStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	if m := d.mapped; m != nil {
		has := m.set != nil && m.set.Has(metadata.RuleHost())
		runtime.KeepAlive(m)
		return has
	}
	return d.domainSet != nil && d.domainSet.Has(metadata.RuleHost())
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) Reset() {
	d.domainSetBuilder.Reset()
	d.domainSet = nil
	d.count = 0
	d.stubbed, d.mapped = false, nil
}

func (d *domainStrategy) Insert(rule string) {
	if d.stubbed {
		log.Warnln("domain rule [%s] follows a compiled set; ignored", rule)
		return
	}
	if d.count == 0 && loadMappedSetStub(rule, ClashDomainSetStubType, d.stubDirectory, func(path string, sum [32]byte) error {
		d.stubbed = true
		m, err := openMappedDomainSet(path, sum)
		if err == nil {
			_, _, d.count, _ = parseMappedSetStub(rule, ClashDomainSetStubType, d.stubDirectory)
			d.mapped = m
		}
		return err
	}) {
		return
	}
	if strings.ContainsRune(rule, '/') {
		log.Warnln("skip invalid domain from rule provider: invalid domain %q: slash is not allowed", rule)
		return
	}
	err := d.domainSetBuilder.Insert(rule)
	if err != nil {
		log.Warnln("skip invalid domain from rule provider: %s", err)
	} else {
		d.count++
	}
}

func (d *domainStrategy) FinishInsert() {
	if d.stubbed {
		return
	}
	d.domainSet = d.domainSetBuilder.Build()
}

func (d *domainStrategy) FromMrs(r io.Reader, count int) error {
	domainSet, err := trie.ReadDomainSetBin(r)
	if err != nil {
		return err
	}
	d.count = count
	d.domainSet = domainSet
	return nil
}

func (d *domainStrategy) WriteMrs(w io.Writer) error {
	if d.domainSet == nil {
		return errors.New("nil domainSet")
	}
	return d.domainSet.WriteBin(w)
}

// DumpMrs emits a compact domain rule list in lexicographical order through f.
// A "domain" entry and a ".domain" entry are represented by one "+.domain" rule;
// either entry alone is emitted unchanged. Returning false from f stops iteration.
func (d *domainStrategy) DumpMrs(f func(key string) bool) {
	if d.domainSet != nil {
		var keys []string
		d.domainSet.Foreach(func(key string) bool {
			keys = append(keys, key)
			return true
		})

		// Group exact and suffix-only entries for the same domain.
		// Set entries are unique, so each group contains at most two entries.
		slices.SortFunc(keys, func(left, right string) int {
			left = strings.TrimPrefix(left, ".")
			right = strings.TrimPrefix(right, ".")
			return strings.Compare(left, right)
		})
		for index := 0; index+1 < len(keys); index++ {
			domain := strings.TrimPrefix(keys[index], ".")
			if domain == strings.TrimPrefix(keys[index+1], ".") {
				// Both the domain itself and its subdomains are covered by one "+." rule.
				keys[index] = "+." + domain
				keys[index+1] = ""
				index++
			}
		}
		keys = slices.DeleteFunc(keys, func(key string) bool { return key == "" })
		// Sort the compact rules by their full text, including wildcard prefixes.
		slices.Sort(keys)

		for _, key := range keys {
			if !f(key) {
				return
			}
		}
	}
}

var _ mrsRuleStrategy = (*domainStrategy)(nil)

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
