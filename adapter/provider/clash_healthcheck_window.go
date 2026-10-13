package provider

import (
	"container/heap"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/common/singledo"
	C "github.com/ProjectClash/Clash/constant"

	"github.com/dlclark/regexp2"
)

const (
	roundWindow = 1000
	roundBestKnown = 64
	roundPriority = roundWindow / 2
)

func (hc *HealthCheck) windows(proxies C.ProxyList) func(url string) C.ProxyList {
	if proxies.Len() <= roundWindow {
		return func(string) C.ProxyList { return proxies }
	}
	base, chosen := proxies, []int(nil)
	if first, ok := proxies.(*chosenFirstList); ok {
		base, chosen = first.base, first.chosen
	}
	lists := map[string]C.ProxyList{}
	for _, u := range hc.urlFilters() {
		lists[u.url] = hc.windowFor(base, chosen, u)
	}
	return func(url string) C.ProxyList {
		if list, ok := lists[url]; ok {
			return list
		}
		return proxies
	}
}

func (hc *HealthCheck) windowFor(base C.ProxyList, chosen []int, u urlFilter) C.ProxyList {
	n := base.Len()
	measures := func(i int) bool {
		if u.filter == nil {
			return true
		}
		match, _ := u.filter.MatchString(base.At(i).Name())
		return match
	}
	at := make([]int, 0, roundWindow)
	taken := make(map[int]struct{}, roundWindow)
	take := func(i int, limit int) {
		if _, ok := taken[i]; !ok && len(at) < limit {
			taken[i] = struct{}{}
			at = append(at, i)
		}
	}
	for _, i := range chosen {
		if measures(i) {
			take(i, roundPriority)
		}
	}
	for _, i := range fastestKnown(base, u, roundBestKnown) {
		take(i, roundPriority)
	}

	hc.windowMu.Lock()
	defer hc.windowMu.Unlock()
	if hc.windowNext == nil {
		hc.windowNext = map[string]int{}
	}
	start := hc.windowNext[u.url] % n
	walked := 0
	for ; walked < n && len(at) < roundWindow; walked++ {
		if i := (start + walked) % n; measures(i) {
			take(i, roundWindow)
		}
	}
	hc.windowNext[u.url] = (start + walked) % n
	return &windowList{base: base, at: at}
}

type urlFilter struct {
	url    string
	filter *regexp2.Regexp
}

func (hc *HealthCheck) urlFilters() []urlFilter {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	urls := make([]urlFilter, 0, 1+len(hc.extra))
	if hc.url != "" {
		urls = append(urls, urlFilter{url: hc.url})
	}
	for url, option := range hc.extra {
		if url == hc.url {
			continue
		}
		var filter *regexp2.Regexp
		if option != nil && len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for f := range option.filters {
				filters = append(filters, f)
			}
			filter = regexp2.MustCompile(strings.Join(filters, "|"), regexp2.None)
		}
		urls = append(urls, urlFilter{url: url, filter: filter})
	}
	return urls
}

func fastestKnown(proxies C.ProxyList, u urlFilter, k int) []int {
	kept := &slowestFirst{}
	var scratch []adapter.URLDelay
	for i := 0; i < proxies.Len(); i++ {
		proxy := proxies.At(i)
		delay, ok := aliveDelay(proxy, u.url, &scratch)
		if !ok || (kept.Len() == k && delay >= (*kept)[0].delay) {
			continue
		}
		if u.filter != nil {
			if match, _ := u.filter.MatchString(proxy.Name()); !match {
				continue
			}
		}
		if kept.Len() < k {
			heap.Push(kept, knownDelay{index: i, delay: delay})
		} else {
			(*kept)[0] = knownDelay{index: i, delay: delay}
			heap.Fix(kept, 0)
		}
	}
	fastest := make([]int, kept.Len())
	for j := len(fastest) - 1; j >= 0; j-- {
		fastest[j] = heap.Pop(kept).(knownDelay).index
	}
	return fastest
}

func aliveDelay(proxy C.Proxy, url string, scratch *[]adapter.URLDelay) (uint16, bool) {
	if records, ok := proxy.(*adapter.Proxy); ok {
		*scratch = records.AppendURLDelays((*scratch)[:0])
		for _, state := range *scratch {
			if state.URL == url {
				return state.Record.Delay, state.Recorded && state.Alive && state.Record.Delay > 0
			}
		}
		return 0, false
	}
	reader, ok := proxy.(urlTestRecordReader)
	if !ok {
		return 0, false
	}
	record, alive, _, ok := reader.LastURLTestRecord(url)
	return record.Delay, ok && alive && record.Delay > 0
}

type knownDelay struct {
	index int
	delay uint16
}

type slowestFirst []knownDelay

func (h slowestFirst) Len() int { return len(h) }
func (h slowestFirst) Less(i, j int) bool {
	if h[i].delay != h[j].delay {
		return h[i].delay > h[j].delay
	}
	return h[i].index > h[j].index
}
func (h slowestFirst) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *slowestFirst) Push(x any)   { *h = append(*h, x.(knownDelay)) }
func (h *slowestFirst) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

type windowList struct {
	base C.ProxyList
	at   []int
}

func (l *windowList) Len() int         { return len(l.at) }
func (l *windowList) At(i int) C.Proxy { return l.base.At(l.at[i]) }

func (bp *baseProvider) HealthCheckAfterDialFailures(failed ...string) {
	hc := bp.healthCheck
	hc.failedFirst.add(failed...)
	hc.round(hc.forcedFlight(), time.Time{}, true)
}

type failedNames struct {
	mu    sync.Mutex
	names []string
}

const failedNamesLimit = 16

func (f *failedNames) add(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range names {
		f.names = slices.DeleteFunc(f.names, func(known string) bool { return known == name })
		f.names = append(f.names, name)
	}
	if extra := len(f.names) - failedNamesLimit; extra > 0 {
		f.names = slices.Delete(f.names, 0, extra)
	}
}

func (f *failedNames) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := f.names
	f.names = nil
	return names
}

func (hc *HealthCheck) checkLoaded() {
	hc.round(hc.forcedFlight(), time.Time{}, true)
}

func (hc *HealthCheck) forcedFlight() *singledo.Single[struct{}] {
	if hc.snapshotProxies().Len() <= roundWindow {
		return hc.singleDo
	}
	return hc.forcedDo
}

func (r *networkChangeRounds) isRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}
