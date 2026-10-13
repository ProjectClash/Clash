package outboundgroup

import (
	"bytes"
	"strconv"

	"github.com/ProjectClash/Clash/adapter"
	C "github.com/ProjectClash/Clash/constant"
)


func appendGroupString(b []byte, key, value string) []byte {
	b = append(b, ',', '"')
	b = append(b, key...)
	b = append(b, '"', ':')
	return adapter.AppendJSONString(b, value)
}

func appendMemberNames(b []byte, proxies C.ProxyList, nilWhenEmpty bool) []byte {
	if proxies.Len() == 0 && nilWhenEmpty {
		return append(b, "null"...)
	}
	size := 2
	for i := 0; i < proxies.Len(); i++ {
		size += len(proxies.At(i).Name()) + 3
	}
	if cap(b)-len(b) < size {
		b = append(make([]byte, 0, len(b)+size+256), b...)
	}
	b = append(b, '[')
	for i := 0; i < proxies.Len(); i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = adapter.AppendJSONString(b, proxies.At(i).Name())
	}
	return append(b, ']')
}

func (s *Selector) ClashAppendJSON(b []byte) []byte { return s.clashAppendJSON(b, s.Members(false)) }

func (s *Selector) ClashAppendSummaryJSON(b []byte) []byte {
	return clashSummarize(b, s.clashAppendJSON(nil, C.ProxySlice(nil)), s.Members(false).Len())
}

func (s *Selector) clashAppendJSON(b []byte, members C.ProxyList) []byte {
	var url string
	if s.testUrl != C.DefaultTestURL {
		url = s.testUrl
	}
	b = append(b, `{"all":`...)
	b = appendMemberNames(b, members, false)
	b = appendGroupString(b, "emptyFallback", s.EmptyFallback().Name())
	b = append(b, `,"hidden":`...)
	b = strconv.AppendBool(b, s.Hidden())
	b = appendGroupString(b, "icon", s.Icon())
	b = appendGroupString(b, "now", s.Now())
	b = appendGroupString(b, "testUrl", url)
	b = appendGroupString(b, "type", s.Type().String())
	return append(b, '}')
}

func (u *URLTest) ClashAppendJSON(b []byte) []byte { return u.clashAppendJSON(b, u.Members(false)) }

func (u *URLTest) ClashAppendSummaryJSON(b []byte) []byte {
	return clashSummarize(b, u.clashAppendJSON(nil, C.ProxySlice(nil)), u.Members(false).Len())
}

func (u *URLTest) clashAppendJSON(b []byte, members C.ProxyList) []byte {
	b = append(b, `{"all":`...)
	b = appendMemberNames(b, members, false)
	b = appendGroupString(b, "emptyFallback", u.EmptyFallback().Name())
	b = appendGroupString(b, "expectedStatus", u.expectedStatus)
	b = appendGroupString(b, "fixed", u.selected.Load())
	b = append(b, `,"hidden":`...)
	b = strconv.AppendBool(b, u.Hidden())
	b = appendGroupString(b, "icon", u.Icon())
	b = appendGroupString(b, "now", u.Now())
	b = appendGroupString(b, "testUrl", u.testUrl)
	b = appendGroupString(b, "type", u.Type().String())
	return append(b, '}')
}

func (f *Fallback) ClashAppendJSON(b []byte) []byte { return f.clashAppendJSON(b, f.Members(false)) }

func (f *Fallback) ClashAppendSummaryJSON(b []byte) []byte {
	return clashSummarize(b, f.clashAppendJSON(nil, C.ProxySlice(nil)), f.Members(false).Len())
}

func (f *Fallback) clashAppendJSON(b []byte, members C.ProxyList) []byte {
	b = append(b, `{"all":`...)
	b = appendMemberNames(b, members, false)
	b = appendGroupString(b, "emptyFallback", f.EmptyFallback().Name())
	b = appendGroupString(b, "expectedStatus", f.expectedStatus)
	b = appendGroupString(b, "fixed", f.selected.Load())
	b = append(b, `,"hidden":`...)
	b = strconv.AppendBool(b, f.Hidden())
	b = appendGroupString(b, "icon", f.Icon())
	b = appendGroupString(b, "now", f.Now())
	b = appendGroupString(b, "testUrl", f.testUrl)
	b = appendGroupString(b, "type", f.Type().String())
	return append(b, '}')
}

func (lb *LoadBalance) ClashAppendJSON(b []byte) []byte {
	return lb.clashAppendJSON(b, lb.Members(false))
}

func (lb *LoadBalance) ClashAppendSummaryJSON(b []byte) []byte {
	return clashSummarize(b, lb.clashAppendJSON(nil, C.ProxySlice(nil)), lb.Members(false).Len())
}

func (lb *LoadBalance) clashAppendJSON(b []byte, members C.ProxyList) []byte {
	b = append(b, `{"all":`...)
	b = appendMemberNames(b, members, true)
	b = appendGroupString(b, "emptyFallback", lb.EmptyFallback().Name())
	b = appendGroupString(b, "expectedStatus", lb.expectedStatus)
	b = append(b, `,"hidden":`...)
	b = strconv.AppendBool(b, lb.Hidden())
	b = appendGroupString(b, "icon", lb.Icon())
	b = appendGroupString(b, "testUrl", lb.testUrl)
	b = appendGroupString(b, "type", lb.Type().String())
	return append(b, '}')
}

func ClashSelection(group ProxyGroup) (now string, hasNow bool, fixed string, hasFixed bool) {
	switch g := group.(type) {
	case *URLTest:
		return g.Now(), true, g.selected.Load(), true
	case *Fallback:
		return g.Now(), true, g.selected.Load(), true
	case *LoadBalance:
		return "", false, "", false
	}
	return group.Now(), true, "", false
}

func clashSummarize(b, full []byte, total int) []byte {
	for _, empty := range []string{`"all":[],`, `"all":null,`} {
		if bytes.HasPrefix(full[1:], []byte(empty)) {
			full = append(full[:1:1], full[1+len(empty):]...)
			break
		}
	}
	at := bytes.LastIndex(full, []byte(`,"type":`))
	if at < 0 {
		return append(b, full...)
	}
	b = append(b, full[:at]...)
	b = append(b, `,"total":`...)
	b = strconv.AppendInt(b, int64(total), 10)
	return append(b, full[at:]...)
}

func ClashNowMember(group ProxyGroup) (C.Proxy, bool) {
	if _, ok := group.(*LoadBalance); ok {
		return nil, false
	}
	member := group.Unwrap(nil, false)
	return member, member != nil
}
