package clash

import (
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func proxiesJSON(proxies map[string]C.Proxy) string {
	b, err := adapter.AppendProxiesJSON([]byte(`{"proxies":`), proxies)
	if err != nil {
		return mustJSON(map[string]any{"proxies": proxies})
	}
	b = append(b, '}')
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func ProxyDelaysJSON() string {
	proxies, providers, table := tunnel.ProxyTable()
	return bridgeSafeString(proxyDelaysJSON(proxies, providers, table, tunnel.ProxyLibrary()))
}

func ProxyDelaysPageJSON(since int64, after string, limit int32) string {
	proxies, providers, table := tunnel.ProxyTable()
	page := proxyDelaysPage{since: since, after: after, limit: int(max(limit, 0))}
	return bridgeSafeString(proxyDelaysPageJSON(proxies, providers, table, librarySorted([]C.ProxyLibrary{tunnel.ProxyLibrary()}), page))
}

var proxyDelaysProcess = strconv.FormatInt(time.Now().UnixNano(), 36)

var proxyDelaysLength atomic.Int64

func proxyDelaysJSON(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider, table uint64, libraries ...C.ProxyLibrary) string {
	return proxyDelaysPageJSON(proxies, providers, table, librarySorted(libraries), proxyDelaysPage{})
}

type proxyDelaysPage struct {
	since int64
	after string
	limit int
}

func proxyDelaysPageJSON(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider, table uint64, library C.ProxyList, page proxyDelaysPage) string {
	began := time.Now().Add(-time.Second).UnixMilli()
	cursor := parseProxyDelaysCursor(page.after)
	providerNames := make([]string, 0, len(providers))
	var versions uint64
	for name, provider := range providers {
		if provider.VehicleType() == P.Compatible {
			continue
		}
		providerNames = append(providerNames, name)
		versions += uint64(provider.Version())
	}
	sort.Strings(providerNames)
	names := make([]string, 0, len(proxies))
	for name := range proxies {
		names = append(names, name)
	}
	sort.Strings(names)

	last := int(proxyDelaysLength.Load())
	if page.limit > 0 && last > page.limit*512 {
		last = page.limit * 512
	}
	b := make([]byte, 0, last+last/8+256)
	b = append(b, `{"revision":"`...)
	b = append(b, proxyDelaysProcess...)
	b = append(b, '.')
	b = strconv.AppendUint(b, table, 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, versions, 10)
	b = append(b, `","groups":{`...)
	var extra []adapter.URLDelay
	first := true
	for _, name := range names {
		node, ok := proxies[name].(*adapter.Proxy)
		if !ok {
			continue
		}
		group, isGroup := node.Adapter().(outboundgroup.ProxyGroup)
		if !isGroup {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		b = appendJSONString(b, name)
		b = append(b, ':', '{')
		now, hasNow, fixed, hasFixed := outboundgroup.ClashSelection(group)
		comma := false
		if hasNow {
			b = append(b, `"now":`...)
			b = appendJSONString(b, now)
			comma = true
		}
		if hasFixed {
			if comma {
				b = append(b, ',')
			}
			b = append(b, `"fixed":`...)
			b = appendJSONString(b, fixed)
			comma = true
		}
		extra = node.AppendURLDelays(extra[:0])
		record, measured := node.LastDelay()
		if measured || len(extra) > 0 {
			if comma {
				b = append(b, ',')
			}
			b = appendDelayRecords(b, node, record, measured, extra)
		}
		b = append(b, '}')
	}
	emitted, next := 0, ""
	emit := func(name string, proxy C.Proxy, position string) bool {
		if page.limit > 0 && emitted >= page.limit {
			if next == "" {
				next = position
			}
			return false
		}
		var wrote bool
		b, extra, first, wrote = appendProxyDelay(b, name, proxy, extra, first, page.since)
		if wrote {
			emitted++
		}
		return true
	}
	b = append(b, `},"proxies":{`...)
	first = true
	if cursor.section <= proxyDelaysSectionProxies {
		j := 0
		visit := func(name string, proxy C.Proxy) bool {
			if cursor.section == proxyDelaysSectionProxies && name < cursor.name {
				return true
			}
			return emit(name, proxy, proxyDelaysCursor{section: proxyDelaysSectionProxies, name: name}.String())
		}
		more := true
		for _, name := range names {
			for ; more && j < library.Len() && library.At(j).Name() < name; j++ {
				node := library.At(j)
				more = visit(node.Name(), node)
			}
			if more {
				more = visit(name, proxies[name])
			}
		}
		for ; more && j < library.Len(); j++ {
			node := library.At(j)
			more = visit(node.Name(), node)
		}
	}
	b = append(b, `},"providers":{`...)
	wroteProvider := false
	for _, providerName := range providerNames {
		if next != "" {
			break
		}
		if cursor.section == proxyDelaysSectionProviders && providerName < cursor.provider {
			continue
		}
		if wroteProvider {
			b = append(b, ',')
		}
		wroteProvider = true
		b = appendJSONString(b, providerName)
		b = append(b, `:{`...)
		first = true
		list := providers[providerName].ProxyList()
		k := 0
		if cursor.section == proxyDelaysSectionProviders && providerName == cursor.provider {
			k = cursor.index
		}
		for ; k < list.Len(); k++ {
			proxy := list.At(k)
			if !emit(proxy.Name(), proxy, proxyDelaysCursor{section: proxyDelaysSectionProviders, provider: providerName, index: k}.String()) {
				break
			}
		}
		b = append(b, '}')
	}
	b = append(b, `},"now":`...)
	b = strconv.AppendInt(b, began, 10)
	if next != "" {
		b = append(b, `,"next":`...)
		b = appendJSONString(b, next)
	}
	b = append(b, '}')
	if page.limit == 0 {
		proxyDelaysLength.Store(int64(len(b)))
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

type proxyDelaysCursor struct {
	section  int
	name     string
	provider string
	index    int
}

const (
	proxyDelaysSectionStart = iota
	proxyDelaysSectionProxies
	proxyDelaysSectionProviders
)

func (c proxyDelaysCursor) String() string {
	var raw string
	if c.section == proxyDelaysSectionProviders {
		raw = "v" + c.provider + "\x00" + strconv.Itoa(c.index)
	} else {
		raw = "p" + c.name
	}
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func parseProxyDelaysCursor(text string) proxyDelaysCursor {
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(raw) == 0 {
		return proxyDelaysCursor{}
	}
	switch raw[0] {
	case 'p':
		return proxyDelaysCursor{section: proxyDelaysSectionProxies, name: string(raw[1:])}
	case 'v':
		provider, index, ok := strings.Cut(string(raw[1:]), "\x00")
		n, err := strconv.Atoi(index)
		if ok && err == nil && n >= 0 {
			return proxyDelaysCursor{section: proxyDelaysSectionProviders, provider: provider, index: n}
		}
	}
	return proxyDelaysCursor{}
}

func appendProxyDelay(b []byte, name string, proxy C.Proxy, extra []adapter.URLDelay, first bool, since int64) ([]byte, []adapter.URLDelay, bool, bool) {
	node, ok := proxy.(delayNode)
	if !ok {
		return b, extra, first, false
	}
	if _, isGroup := node.Adapter().(outboundgroup.ProxyGroup); isGroup {
		return b, extra, first, false
	}
	extra = node.AppendURLDelays(extra[:0])
	record, measured := node.LastDelay()
	if !measured && len(extra) == 0 {
		return b, extra, first, false
	}
	if since > 0 {
		newest := int64(0)
		if measured {
			newest = record.Time.UnixMilli()
		}
		for _, state := range extra {
			if state.Recorded && state.Record.Time.UnixMilli() > newest {
				newest = state.Record.Time.UnixMilli()
			}
		}
		if newest <= since {
			return b, extra, first, false
		}
	}
	if !first {
		b = append(b, ',')
	}
	b = appendJSONString(b, name)
	b = append(b, ':', '{')
	b = appendDelayRecords(b, node, record, measured, extra)
	return append(b, '}'), extra, false, true
}

func appendDelayRecords(b []byte, node delayNode, record C.DelayHistory, measured bool, extra []adapter.URLDelay) []byte {
	b = append(b, `"alive":`...)
	b = strconv.AppendBool(b, node.AliveForTestUrl(""))
	if measured {
		b = appendDelayRecord(b, record)
	}
	if len(extra) > 0 {
		b = append(b, `,"extra":{`...)
		for i, state := range extra {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendJSONString(b, state.URL)
			b = append(b, `:{"alive":`...)
			b = strconv.AppendBool(b, state.Alive)
			if state.Recorded {
				b = appendDelayRecord(b, state.Record)
			}
			b = append(b, '}')
		}
		b = append(b, '}')
	}
	return b
}

func appendDelayRecord(b []byte, record C.DelayHistory) []byte {
	b = append(b, `,"delay":`...)
	b = strconv.AppendUint(b, uint64(record.Delay), 10)
	b = append(b, `,"time":"`...)
	b = record.Time.AppendFormat(b, time.RFC3339Nano)
	return append(b, '"')
}

func appendJSONString(b []byte, s string) []byte { return adapter.AppendJSONString(b, s) }

type delayNode interface {
	C.Proxy
	adapter.DelayRecords
}

func librarySorted(libraries []C.ProxyLibrary) C.ProxyList {
	for _, library := range libraries {
		if library == nil {
			continue
		}
		if nodes, ok := library.(*adapter.LibraryNodes); ok {
			return nodes.Sorted()
		}
		all := C.ProxiesOf(library)
		sort.Slice(all, func(i, j int) bool { return all[i].Name() < all[j].Name() })
		return C.ProxySlice(all)
	}
	return C.ProxySlice(nil)
}
