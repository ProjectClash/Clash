package adapter

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)


func (p *Proxy) clashAppendJSON(b []byte) (out []byte, ok bool, err error) {
	id, ok := outbound.CatalogNodeID(p.ProxyAdapter)
	if !ok {
		out, ok = p.clashAppendMergedJSON(b)
		return out, ok, nil
	}
	info := p.ProxyInfo()
	b = append(b, `{"alive":`...)
	b = strconv.AppendBool(b, p.alive.Load())
	b = append(b, `,"dialer-proxy":`...)
	b = appendJSONString(b, info.DialerProxy)
	b = append(b, `,"extra":`...)
	if b, err = p.appendExtraJSON(b); err != nil {
		return nil, true, err
	}
	b = append(b, `,"history":`...)
	if b, err = appendDelayHistory(b, p.history.Copy(), false); err != nil {
		return nil, true, err
	}
	b = append(b, `,"id":"`...)
	b = outbound.AppendUUID(b, id)
	b = append(b, `","interface":`...)
	b = appendJSONString(b, info.Interface)
	b = append(b, `,"mptcp":`...)
	b = strconv.AppendBool(b, info.MPTCP)
	b = append(b, `,"name":`...)
	b = appendJSONString(b, p.Name())
	b = append(b, `,"provider-name":`...)
	b = appendJSONString(b, info.ProviderName)
	b = append(b, `,"routing-mark":`...)
	b = strconv.AppendInt(b, int64(info.RoutingMark), 10)
	b = append(b, `,"smux":`...)
	b = strconv.AppendBool(b, info.SMUX)
	b = append(b, `,"tfo":`...)
	b = strconv.AppendBool(b, info.TFO)
	b = append(b, `,"type":`...)
	b = appendJSONString(b, p.Type().String())
	b = append(b, `,"udp":`...)
	b = strconv.AppendBool(b, p.SupportUDP())
	b = append(b, `,"uot":`...)
	b = strconv.AppendBool(b, p.SupportUOT())
	b = append(b, `,"xudp":`...)
	b = strconv.AppendBool(b, info.XUDP)
	return append(b, '}'), true, nil
}

func (p *Proxy) appendExtraJSON(b []byte) ([]byte, error) {
	type urlState struct {
		url   string
		state *internalProxyState
	}
	p.extra.mu.RLock()
	states := make([]urlState, 0, len(p.extra.states))
	for url, state := range p.extra.states {
		states = append(states, urlState{url, state})
	}
	p.extra.mu.RUnlock()
	if len(states) == 0 {
		return append(b, `{}`...), nil
	}
	sort.Slice(states, func(i, j int) bool { return states[i].url < states[j].url })
	b = append(b, '{')
	for i, s := range states {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, s.url)
		b = append(b, `:{"alive":`...)
		b = strconv.AppendBool(b, s.state.alive.Load())
		b = append(b, `,"history":`...)
		var err error
		if b, err = appendDelayHistory(b, s.state.history.Copy(), true); err != nil {
			return nil, err
		}
		b = append(b, '}')
	}
	return append(b, '}'), nil
}

func appendDelayHistory(b []byte, records []C.DelayHistory, nilWhenEmpty bool) ([]byte, error) {
	if len(records) == 0 {
		if nilWhenEmpty {
			return append(b, `null`...), nil
		}
		return append(b, `[]`...), nil
	}
	b = append(b, '[')
	for i, record := range records {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"time":"`...)
		start := len(b)
		b = record.Time.AppendFormat(b, time.RFC3339Nano)
		if !strictRFC3339(b[start:]) {
			_, err := json.Marshal(record)
			return nil, err
		}
		b = append(b, `","delay":`...)
		b = strconv.AppendUint(b, uint64(record.Delay), 10)
		b = append(b, '}')
	}
	return append(b, ']'), nil
}

func strictRFC3339(text []byte) bool {
	if len(text) < len("2006-01-02T15:04:05Z") || text[4] != '-' {
		return false
	}
	if text[len(text)-1] == 'Z' {
		return true
	}
	c := text[len(text)-len("Z07:00")]
	if '0' <= c && c <= '9' {
		return false
	}
	hour := text[len(text)-len("07:00"):]
	return 10*(hour[0]-'0')+(hour[1]-'0') < 24
}

func AppendJSONString(b []byte, s string) []byte { return appendJSONString(b, s) }

func appendJSONString(b []byte, s string) []byte {
	if !jsonPlain(s) {
		encoded, _ := json.Marshal(s)
		return append(b, encoded...)
	}
	b = append(b, '"')
	b = append(b, s...)
	return append(b, '"')
}

func jsonPlain(s string) bool {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c < 0x20 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
				return false
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 || r == ' ' || r == ' ' {
			return false
		}
		i += size
	}
	return true
}

const clashNodeJSONFixed = 260

func (p *Proxy) clashJSONSize() int {
	info := p.ProxyInfo()
	size := clashNodeJSONFixed + len(p.Name()) + len(info.ProviderName) + len(info.DialerProxy) + len(info.Interface) + 12
	records := int(p.history.Len())
	p.extra.mu.RLock()
	for url, state := range p.extra.states {
		size += len(url) + 32
		records += int(state.history.Len())
	}
	p.extra.mu.RUnlock()
	return size + 64*records
}

func AppendProxiesJSON(b []byte, proxies map[string]C.Proxy) ([]byte, error) {
	names := make([]string, 0, len(proxies))
	written := map[string][]byte{}
	size := 2
	for name, proxy := range proxies {
		names = append(names, name)
		size += 2*len(name) + 4
		if node, ok := proxy.(*Proxy); ok {
			if _, catalog := outbound.CatalogNodeID(node.ProxyAdapter); catalog {
				size += node.clashJSONSize()
				continue
			}
		}
		encoded, err := appendProxyJSON(nil, proxy)
		if err != nil {
			return nil, err
		}
		written[name] = encoded
		size += len(encoded)
	}
	sort.Strings(names)
	if cap(b)-len(b) < size {
		b = append(make([]byte, 0, len(b)+size), b...)
	}
	b = append(b, '{')
	for i, name := range names {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, name)
		b = append(b, ':')
		if encoded, ok := written[name]; ok {
			b = append(b, encoded...)
			continue
		}
		var err error
		if b, err = appendProxyJSON(b, proxies[name]); err != nil {
			return nil, err
		}
	}
	return append(b, '}'), nil
}

func appendProxyJSON(b []byte, proxy C.Proxy) ([]byte, error) {
	if proxy == nil {
		return append(b, `null`...), nil
	}
	if node, ok := proxy.(*libraryNode); ok {
		proxy = node.view()
	}
	if node, ok := proxy.(*Proxy); ok {
		out, ok, err := node.clashAppendJSON(b)
		if ok {
			return out, err
		}
		encoded, err := node.MarshalJSON()
		if err != nil {
			return nil, err
		}
		return append(b, encoded...), nil
	}
	encoded, err := json.Marshal(proxy)
	if err != nil {
		return nil, err
	}
	return append(b, encoded...), nil
}

func WriteProxiesJSON(w io.Writer, proxies map[string]C.Proxy, library C.ProxyLibrary) error {
	_, err := WriteProxiesJSONPage(w, proxies, library, "", 0)
	return err
}

func WriteProxiesJSONPage(w io.Writer, proxies map[string]C.Proxy, library C.ProxyLibrary, after string, limit int) (string, error) {
	return WriteProxiesJSONPageFunc(w, proxies, library, after, limit, appendProxyJSON)
}

func AppendProxyJSON(b []byte, proxy C.Proxy) ([]byte, error) { return appendProxyJSON(b, proxy) }

func WriteProxiesJSONPageFunc(w io.Writer, proxies map[string]C.Proxy, library C.ProxyLibrary, after string, limit int,
	appendOne func(b []byte, proxy C.Proxy) ([]byte, error)) (string, error) {
	names := make([]string, 0, len(proxies))
	for name := range proxies {
		names = append(names, name)
	}
	sort.Strings(names)
	var sorted C.ProxyList = C.ProxySlice(nil)
	if nodes, ok := library.(*LibraryNodes); ok && nodes != nil {
		sorted = nodes.Sorted()
	} else if library != nil {
		all := C.ProxiesOf(library)
		sort.Slice(all, func(i, j int) bool { return all[i].Name() < all[j].Name() })
		sorted = C.ProxySlice(all)
	}
	const piece = 64 << 10
	b := make([]byte, 0, piece+4096)
	b = append(b, '{')
	first := true
	write := func(name string, proxy C.Proxy) error {
		if !first {
			b = append(b, ',')
		}
		first = false
		b = appendJSONString(b, name)
		b = append(b, ':')
		var err error
		if b, err = appendOne(b, proxy); err != nil {
			return err
		}
		if len(b) >= piece {
			if _, err := w.Write(b); err != nil {
				return err
			}
			b = b[:0]
		}
		return nil
	}
	i, j := 0, 0
	if after != "" {
		i = sort.SearchStrings(names, after)
		if i < len(names) && names[i] == after {
			i++
		}
		j = sort.Search(sorted.Len(), func(k int) bool { return sorted.At(k).Name() > after })
	}
	written, last, next := 0, "", ""
	for i < len(names) || j < sorted.Len() {
		if limit > 0 && written == limit {
			next = last
			break
		}
		if j >= sorted.Len() || (i < len(names) && names[i] < sorted.At(j).Name()) {
			if err := write(names[i], proxies[names[i]]); err != nil {
				return "", err
			}
			last = names[i]
			i++
		} else {
			node := sorted.At(j)
			if err := write(node.Name(), node); err != nil {
				return "", err
			}
			last = node.Name()
			j++
		}
		written++
	}
	b = append(b, '}')
	_, err := w.Write(b)
	return next, err
}

func ClashHealthCounts(list C.ProxyList) (alive, dead int) {
	if list == nil {
		return 0, 0
	}
	for i := 0; i < list.Len(); i++ {
		var says, tested bool
		switch node := list.At(i).(type) {
		case *Proxy:
			says, tested = node.alive.Load(), node.history.Len() > 0
		case *libraryNode:
			_, says, tested = unpackRecord(node.record.Load())
		case nil:
			continue
		default:
			says, tested = node.AliveForTestUrl(""), len(node.DelayHistory()) > 0
		}
		switch {
		case tested && says:
			alive++
		case tested:
			dead++
		}
	}
	return alive, dead
}
