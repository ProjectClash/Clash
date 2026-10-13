package provider

import (
	"slices"

	"github.com/ProjectClash/Clash/common/atomic"
	C "github.com/ProjectClash/Clash/constant"
)

var healthCheckFirst = atomic.NewTypedValue[func() map[string]struct{}](nil)

func SetHealthCheckFirst(f func() map[string]struct{}) {
	healthCheckFirst.Store(f)
}

func chosenFirst(proxies C.ProxyList, failed ...string) C.ProxyList {
	var chosen map[string]struct{}
	if first := healthCheckFirst.Load(); first != nil {
		chosen = first()
	}
	if len(chosen) == 0 && len(failed) == 0 {
		return proxies
	}
	failing := make(map[string]struct{}, len(failed))
	for _, name := range failed {
		failing[name] = struct{}{}
	}
	var failedAt, chosenAt []int
	for i := 0; i < proxies.Len(); i++ {
		name := proxies.At(i).Name()
		if _, ok := failing[name]; ok {
			failedAt = append(failedAt, i)
		} else if _, ok := chosen[name]; ok {
			chosenAt = append(chosenAt, i)
		}
	}
	at := append(failedAt, chosenAt...)
	if len(at) == 0 {
		return proxies
	}
	sorted := slices.Clone(at)
	slices.Sort(sorted)
	return &chosenFirstList{base: proxies, chosen: at, sorted: sorted}
}

type chosenFirstList struct {
	base   C.ProxyList
	chosen []int
	sorted []int
}

func (l *chosenFirstList) Len() int { return l.base.Len() }

func (l *chosenFirstList) At(i int) C.Proxy {
	if i < len(l.chosen) {
		return l.base.At(l.chosen[i])
	}
	at := i - len(l.chosen)
	for _, c := range l.sorted {
		if c > at {
			break
		}
		at++
	}
	return l.base.At(at)
}
