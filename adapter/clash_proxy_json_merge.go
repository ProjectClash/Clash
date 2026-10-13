package adapter

import (
	"bytes"
	"encoding/json"
	"strconv"
	"unsafe"

	C "github.com/ProjectClash/Clash/constant"
)


func (p *Proxy) clashAppendMergedJSON(b []byte) (out []byte, ok bool) {
	return p.clashAppendMergedJSONOf(b, false)
}

func AppendProxySummaryJSON(b []byte, proxy C.Proxy) ([]byte, error) {
	if node, ok := proxy.(*Proxy); ok {
		if _, isGroup := node.ProxyAdapter.(interface{ ClashAppendSummaryJSON([]byte) []byte }); isGroup {
			if out, ok := node.clashAppendMergedJSONOf(b, true); ok {
				return out, nil
			}
		}
	}
	return appendProxyJSON(b, proxy)
}

func (p *Proxy) clashAppendMergedJSONOf(b []byte, summary bool) (out []byte, ok bool) {
	var inner []byte
	if writer, ok := p.ProxyAdapter.(interface{ ClashAppendSummaryJSON([]byte) []byte }); ok && summary {
		inner = writer.ClashAppendSummaryJSON(nil)
	} else if writer, ok := p.ProxyAdapter.(interface{ ClashAppendJSON([]byte) []byte }); ok {
		inner = writer.ClashAppendJSON(nil)
	} else {
		var err error
		if inner, err = p.ProxyAdapter.MarshalJSON(); err != nil {
			return b, false
		}
	}
	members, ok := canonicalMembers(inner)
	if !ok {
		return b, false
	}
	info := p.ProxyInfo()
	fields := []jsonMember{
		{key: "alive", value: strconv.AppendBool(nil, p.alive.Load())},
		{key: "dialer-proxy", value: appendJSONString(nil, info.DialerProxy)},
		{key: "interface", value: appendJSONString(nil, info.Interface)},
		{key: "mptcp", value: strconv.AppendBool(nil, info.MPTCP)},
		{key: "name", value: appendJSONString(nil, p.Name())},
		{key: "provider-name", value: appendJSONString(nil, info.ProviderName)},
		{key: "routing-mark", value: strconv.AppendInt(nil, int64(info.RoutingMark), 10)},
		{key: "smux", value: strconv.AppendBool(nil, info.SMUX)},
		{key: "tfo", value: strconv.AppendBool(nil, info.TFO)},
		{key: "udp", value: strconv.AppendBool(nil, p.SupportUDP())},
		{key: "uot", value: strconv.AppendBool(nil, p.SupportUOT())},
		{key: "xudp", value: strconv.AppendBool(nil, info.XUDP)},
	}
	var err error
	extra, err := p.appendExtraJSON(nil)
	if err != nil {
		return b, false
	}
	history, err := appendDelayHistory(nil, p.history.Copy(), false)
	if err != nil {
		return b, false
	}
	fields = append(fields, jsonMember{key: "extra", value: extra}, jsonMember{key: "history", value: history})
	for _, member := range members {
		replaced := false
		for _, field := range fields {
			if field.key == member.key {
				replaced = true
				break
			}
		}
		if !replaced {
			fields = append(fields, member)
		}
	}
	sortMembers(fields)
	if size := len(inner) + 512; cap(b)-len(b) < size {
		b = append(make([]byte, 0, len(b)+size), b...)
	}
	b = append(b, '{')
	for i, field := range fields {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, field.key)
		b = append(b, ':')
		b = append(b, field.value...)
	}
	return append(b, '}'), true
}

type jsonMember struct {
	key   string
	value []byte
}

func sortMembers(members []jsonMember) {
	for i := 1; i < len(members); i++ {
		for j := i; j > 0 && members[j].key < members[j-1].key; j-- {
			members[j], members[j-1] = members[j-1], members[j]
		}
	}
}

func canonicalMembers(data []byte) ([]jsonMember, bool) {
	s := jsonScan{data: data}
	var members []jsonMember
	if !s.object(func(key string, value []byte) bool {
		members = append(members, jsonMember{key: key, value: value})
		return true
	}) || s.i != len(data) {
		return nil, false
	}
	return members, true
}

type jsonScan struct {
	data []byte
	i    int
}

func (s *jsonScan) peek() byte {
	if s.i < len(s.data) {
		return s.data[s.i]
	}
	return 0
}

func (s *jsonScan) object(member func(key string, value []byte) bool) bool {
	if s.peek() != '{' {
		return false
	}
	s.i++
	if s.peek() == '}' {
		s.i++
		return true
	}
	previous, first := "", true
	for {
		key, ok := s.string()
		if !ok || (!first && key <= previous) || s.peek() != ':' {
			return false
		}
		previous, first = key, false
		s.i++
		start := s.i
		if !s.value() || !member(key, s.data[start:s.i]) {
			return false
		}
		switch s.peek() {
		case ',':
			s.i++
		case '}':
			s.i++
			return true
		default:
			return false
		}
	}
}

func (s *jsonScan) value() bool {
	switch c := s.peek(); {
	case c == '{':
		return s.object(func(string, []byte) bool { return true })
	case c == '[':
		s.i++
		if s.peek() == ']' {
			s.i++
			return true
		}
		for {
			if !s.value() {
				return false
			}
			switch s.peek() {
			case ',':
				s.i++
			case ']':
				s.i++
				return true
			default:
				return false
			}
		}
	case c == '"':
		_, ok := s.scanString(false)
		return ok
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || c >= '0' && c <= '9':
		return s.integer()
	}
	return false
}

func (s *jsonScan) literal(word string) bool {
	if !bytes.HasPrefix(s.data[s.i:], []byte(word)) {
		return false
	}
	s.i += len(word)
	return true
}

func (s *jsonScan) integer() bool {
	start := s.i
	if s.peek() == '-' {
		s.i++
	}
	digits := s.i
	for c := s.peek(); c >= '0' && c <= '9'; c = s.peek() {
		s.i++
	}
	n := s.i - digits
	if n == 0 || n > 15 || (n > 1 && s.data[digits] == '0') || s.data[start:s.i][0] == '-' && n == 1 && s.data[digits] == '0' {
		return false
	}
	switch s.peek() {
	case '.', 'e', 'E':
		return false
	}
	return true
}

func (s *jsonScan) string() (string, bool) { return s.scanString(true) }

func (s *jsonScan) scanString(decode bool) (string, bool) {
	if s.peek() != '"' {
		return "", false
	}
	start := s.i
	s.i++
	plain := true
	segment := s.i
	for {
		if s.i >= len(s.data) {
			return "", false
		}
		c := s.data[s.i]
		if c == '"' {
			break
		}
		if c != '\\' {
			s.i++
			continue
		}
		if !jsonPlainBytes(s.data[segment:s.i]) {
			return "", false
		}
		if s.i+1 >= len(s.data) {
			return "", false
		}
		switch s.data[s.i+1] {
		case '"', '\\', 'n', 'r', 't':
			s.i += 2
		case 'u':
			if s.i+6 > len(s.data) {
				return "", false
			}
			switch string(s.data[s.i+2 : s.i+6]) {
			case "003c", "003e", "0026":
			default:
				plain = false
			}
			s.i += 6
		default:
			plain = false
			s.i += 2
		}
		segment = s.i
	}
	if !jsonPlainBytes(s.data[segment:s.i]) {
		return "", false
	}
	s.i++
	raw := s.data[start:s.i]
	if plain && !decode {
		return "", true
	}
	if !bytes.ContainsRune(raw, '\\') {
		return string(raw[1 : len(raw)-1]), true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	if !plain && !bytes.Equal(appendJSONString(nil, value), raw) {
		return "", false
	}
	return value, true
}

func jsonPlainBytes(b []byte) bool {
	return jsonPlain(unsafe.String(unsafe.SliceData(b), len(b)))
}
