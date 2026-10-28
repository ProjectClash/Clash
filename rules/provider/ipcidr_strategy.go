package provider

import (
	"errors"
	"io"
	"net/netip"
	"runtime"

	"github.com/ProjectClash/Clash/component/cidr"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"

	"go4.org/netipx"
)

type ipcidrStrategy struct {
	count   int
	cidrSet *cidr.IpCidrSet
	//trie    *trie.IpCidrTrie
	stubDirectory string
	stubbed       bool
	mapped        *mappedIPSet
}

func (i *ipcidrStrategy) Behavior() P.RuleBehavior {
	return P.IPCIDR
}

func (i *ipcidrStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	if helper.ResolveIP != nil {
		helper.ResolveIP()
	}
	if m := i.mapped; m != nil {
		has := metadata.DstIP.IsValid() && m.set.MatchIp(metadata.DstIP)
		runtime.KeepAlive(m)
		return has
	}
	// return i.trie != nil && i.trie.IsContain(metadata.DstIP.AsSlice())
	return i.cidrSet != nil && i.cidrSet.IsContain(metadata.DstIP)
}

func (i *ipcidrStrategy) Count() int {
	return i.count
}

func (i *ipcidrStrategy) Reset() {
	// i.trie = trie.NewIpCidrTrie()
	i.cidrSet = cidr.NewIpCidrSet()
	i.count = 0
	i.stubbed, i.mapped = false, nil
}

func (i *ipcidrStrategy) Insert(rule string) {
	if i.stubbed {
		log.Warnln("IP rule [%s] follows a compiled set; ignored", rule)
		return
	}
	if i.count == 0 && loadMappedSetStub(rule, ClashIPCidrSetStubType, i.stubDirectory, func(path string, sum [32]byte) error {
		i.stubbed = true
		m, err := openMappedIPSet(path, &sum)
		if err == nil {
			_, _, i.count, _ = parseMappedSetStub(rule, ClashIPCidrSetStubType, i.stubDirectory)
			i.mapped = m
		}
		return err
	}) {
		return
	}
	//err := i.trie.AddIpCidrForString(rule)
	err := i.cidrSet.AddIpCidrForString(rule)
	if err != nil {
		log.Warnln("invalid Ipcidr:[%s]", rule)
	} else {
		i.count++
	}
}

func (i *ipcidrStrategy) FinishInsert() {
	if i.stubbed {
		return
	}
	i.cidrSet.Merge()
}

func (i *ipcidrStrategy) FromMrs(r io.Reader, count int) error {
	cidrSet, err := cidr.ReadIpCidrSet(r)
	if err != nil {
		return err
	}
	i.count = count
	i.cidrSet = cidrSet
	return nil
}

func (i *ipcidrStrategy) WriteMrs(w io.Writer) error {
	if i.cidrSet == nil {
		return errors.New("nil cidrSet")
	}
	return i.cidrSet.WriteBin(w)
}

func (i *ipcidrStrategy) DumpMrs(f func(key string) bool) {
	if i.cidrSet != nil {
		i.cidrSet.Foreach(func(prefix netip.Prefix) bool {
			return f(prefix.String())
		})
	}
}

func (i *ipcidrStrategy) ToIpCidr() *netipx.IPSet {
	if m := i.mapped; m != nil {
		set := m.set.ToIPSet()
		runtime.KeepAlive(m)
		return set
	}
	return i.cidrSet.ToIPSet()
}

func NewIPCidrStrategy() *ipcidrStrategy {
	return &ipcidrStrategy{}
}
