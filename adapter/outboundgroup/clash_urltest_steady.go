package outboundgroup

import C "github.com/ProjectClash/Clash/constant"

func keptChoiceWhenAllDown(current, best C.Proxy, members C.ProxyList, url string) (C.Proxy, bool) {
	if current == nil || best.AliveForTestUrl(url) {
		return nil, false
	}
	for i := 0; i < members.Len(); i++ {
		if member := members.At(i); member.Name() == current.Name() {
			return member, true
		}
	}
	return nil, false
}
