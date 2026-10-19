package common

import (
	"net/netip"

	C "github.com/ProjectClash/Clash/constant"
)

func (i *IPCIDR) ClashResolvesIP() bool {
	return !i.noResolveIP && !i.isSourceIP
}

func (i *IPCIDR) ClashIsSourceIP() bool {
	return i.RuleType() == C.SrcIPCIDR
}

func (i *IPCIDR) ClashPrefix() netip.Prefix {
	return i.ipnet
}
