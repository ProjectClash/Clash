package clash

import (
	"context"
	"fmt"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/profile/cachefile"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const defaultURLTestURL = "https://www.gstatic.com/generate_204"

func SelectProxy(group, name string) error {
	proxy, ok := tunnel.Proxies()[group]
	if !ok {
		return bridgeSafeError(fmt.Errorf("clash: proxy group %q not found", group))
	}
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		return bridgeSafeError(fmt.Errorf("clash: %q is not a selectable group", group))
	}
	if err := selector.Set(name); err != nil {
		return bridgeSafeError(fmt.Errorf("clash: select %q in %q: %w", name, group, err))
	}
	cachefile.Cache().SetSelected(group, name)
	return nil
}

func UnfixProxy(group string) error {
	proxy, ok := tunnel.Proxies()[group]
	if !ok {
		return bridgeSafeError(fmt.Errorf("clash: proxy group %q not found", group))
	}
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		return bridgeSafeError(fmt.Errorf("clash: %q is not a selectable group", group))
	}
	if _, manual := proxy.Adapter().(*outboundgroup.Selector); manual {
		return bridgeSafeError(fmt.Errorf("clash: %q is a selector; only automatic groups unfix", group))
	}
	selector.ForceSet("")
	cachefile.Cache().SetSelected(group, "")
	return nil
}

var urlTestExpectedStatus = mustStatusRanges("200-299")

func mustStatusRanges(spec string) utils.IntRanges[uint16] {
	ranges, err := utils.NewUnsignedRanges[uint16](spec)
	if err != nil {
		panic("clash: invalid URL test status range " + spec + ": " + err.Error())
	}
	return ranges
}

func URLTest(name, url string) int32 {
	proxy, ok := tunnel.Proxies()[name]
	if !ok {
		proxy, ok = proxyFromProviders(name)
		if !ok {
			return -1
		}
	}
	return urlTestDelay(proxy, url)
}

func proxyFromProviders(name string) (C.Proxy, bool) {
	var found C.Proxy
	for _, prov := range tunnel.Providers() {
		for _, proxy := range prov.Proxies() {
			if proxy.Name() != name {
				continue
			}
			if found != nil {
				return nil, false
			}
			found = proxy
		}
	}
	return found, found != nil
}

func urlTestDelay(proxy C.Proxy, url string) int32 {
	if url == "" {
		url = defaultURLTestURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if outcomes, ok := proxy.(adapter.URLTestOutcomeProvider); ok {
		outcome, err := outcomes.URLTestOutcome(ctx, url, urlTestExpectedStatus)
		if err != nil || !outcome.Satisfied {
			return -1
		}
		return int32(outcome.Delay)
	}
	delay, err := proxy.URLTest(ctx, url, nil)
	if err != nil {
		return -1
	}
	return int32(delay)
}

func CloseConnection(id string) bool {
	if c := statistic.DefaultManager.Get(id); c != nil {
		_ = c.Close()
		return true
	}
	return false
}

func CloseAllConnections() {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
}
