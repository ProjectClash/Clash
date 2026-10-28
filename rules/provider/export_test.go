package provider

import (
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules/common"
)

func NewClassicalStrategyInIndexDirectory(parse common.ParseRuleFunc, directory string) *classicalStrategy {
	s := NewClassicalStrategy(parse)
	s.indexDirectory = directory
	return s
}

func UseTestTunnel(t *testing.T) {
	old := tunnel
	SetTunnel(publicationTunnel{utils.NewCallback[P.RuleProvider]()})
	t.Cleanup(func() { SetTunnel(old) })
}

func NewDomainStrategyInStubDirectory(directory string) *domainStrategy {
	s := NewDomainStrategy()
	s.stubDirectory = directory
	return s
}

func NewIPCidrStrategyInStubDirectory(directory string) *ipcidrStrategy {
	s := NewIPCidrStrategy()
	s.Reset()
	s.stubDirectory = directory
	return s
}

func ParseMrsDomainForTest(provider string, mrs []byte) (*domainStrategy, error) {
	s := NewDomainStrategy()
	_, err := clashProviderParse(provider, mrs, s, P.MrsRule)
	return s, err
}

func ParseMrsIPCidrForTest(provider string, mrs []byte) (*ipcidrStrategy, error) {
	s := NewIPCidrStrategy()
	_, err := clashProviderParse(provider, mrs, s, P.MrsRule)
	return s, err
}

func HelperParseMrsDomainForTest(mrs []byte) (*domainStrategy, error) {
	s := NewDomainStrategy()
	_, err := rulesParse(mrs, s, P.MrsRule)
	return s, err
}

func MrsMappedCacheGenerationForTest() string {
	clashMrsCache.Lock()
	defer clashMrsCache.Unlock()
	return clashMrsCache.generation
}

func (d *domainStrategy) MappedForTest() bool { return d.mapped != nil && d.domainSet == nil }

func (i *ipcidrStrategy) MappedForTest() bool { return i.mapped != nil && i.cidrSet == nil }

func MrsMappedCacheWritesForTest() int64 { return clashMrsCacheWrites.Load() }

var ClashMrsReaderForTest = clashMrsReader
