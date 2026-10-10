package provider

import "github.com/ProjectClash/Clash/component/profile/cachefile"

func (pp *proxySetProvider) ClashSetSubscriptionInfo(userinfo string) {
	if userinfo == "" {
		return
	}
	cachefile.Cache().SetSubscriptionInfo(pp.Name(), userinfo)
	pp.subscriptionInfo = NewSubscriptionInfo(userinfo)
}
