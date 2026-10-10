package common

import C "github.com/ProjectClash/Clash/constant"

func (i *IPCIDR) ClashResolvesIP() bool {
	return !i.noResolveIP && !i.isSourceIP
}

func (i *IPCIDR) ClashIsSourceIP() bool {
	return i.RuleType() == C.SrcIPCIDR
}
