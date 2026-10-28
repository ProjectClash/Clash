package constant

import "sort"


type ProxyList interface {
	Len() int
	At(i int) Proxy
}

type ProxySlice []Proxy

func (s ProxySlice) Len() int       { return len(s) }
func (s ProxySlice) At(i int) Proxy { return s[i] }

type ProxyLibrary interface {
	ProxyList
	Lookup(name string) (Proxy, bool)
}

func ProxiesOf(list ProxyList) []Proxy {
	if list == nil {
		return nil
	}
	if s, ok := list.(ProxySlice); ok {
		return s
	}
	proxies := make([]Proxy, list.Len())
	for i := range proxies {
		proxies[i] = list.At(i)
	}
	return proxies
}

func ConcatProxyLists(lists ...ProxyList) ProxyList {
	kept := make([]ProxyList, 0, len(lists))
	for _, list := range lists {
		if list != nil && list.Len() > 0 {
			kept = append(kept, list)
		}
	}
	switch len(kept) {
	case 0:
		return ProxySlice(nil)
	case 1:
		return kept[0]
	}
	concat := &concatProxyList{lists: kept, ends: make([]int, len(kept))}
	end := 0
	for i, list := range kept {
		end += list.Len()
		concat.ends[i] = end
	}
	return concat
}

type concatProxyList struct {
	lists []ProxyList
	ends  []int
}

func (c *concatProxyList) Len() int { return c.ends[len(c.ends)-1] }

func (c *concatProxyList) At(i int) Proxy {
	list := sort.Search(len(c.ends), func(j int) bool { return c.ends[j] > i })
	if list > 0 {
		i -= c.ends[list-1]
	}
	return c.lists[list].At(i)
}

func IndexedProxyList(base ProxyList, indexes []uint32) ProxyList {
	return &indexedProxyList{base: base, indexes: indexes}
}

type indexedProxyList struct {
	base    ProxyList
	indexes []uint32
}

func (l *indexedProxyList) Len() int       { return len(l.indexes) }
func (l *indexedProxyList) At(i int) Proxy { return l.base.At(int(l.indexes[i])) }

func SubProxyList(base ProxyList, from, to int) ProxyList {
	return &subProxyList{base: base, from: from, n: to - from}
}

type subProxyList struct {
	base    ProxyList
	from, n int
}

func (l *subProxyList) Len() int       { return l.n }
func (l *subProxyList) At(i int) Proxy { return l.base.At(l.from + i) }

func ProxyListWithout(base ProxyList, positions []int) ProxyList {
	if len(positions) == 0 {
		return base
	}
	return &proxyListWithout{base: base, skip: positions}
}

type proxyListWithout struct {
	base ProxyList
	skip []int
}

func (l *proxyListWithout) Len() int { return l.base.Len() - len(l.skip) }

func (l *proxyListWithout) At(i int) Proxy {
	for _, at := range l.skip {
		if at > i {
			break
		}
		i++
	}
	return l.base.At(i)
}
