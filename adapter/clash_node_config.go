package adapter

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
)


const (
	cfgNil byte = iota
	cfgFalse
	cfgTrue
	cfgString
	cfgWord
	cfgUUID
	cfgInt
	cfgInt8
	cfgInt16
	cfgInt32
	cfgInt64
	cfgUint
	cfgUint8
	cfgUint16
	cfgUint32
	cfgUint64
	cfgFloat32
	cfgFloat64
	cfgList
	cfgStrings
	cfgMap
	cfgStringMap
	cfgAnyMap
	cfgMapList
)

var nodeConfigWords = [...]string{
	"name", "type", "server", "port", "password", "cipher", "udp", "uuid", "alterId", "network",
	"tls", "sni", "servername", "skip-cert-verify", "client-fingerprint", "ws-opts", "path",
	"headers", "Host", "host", "grpc-opts", "grpc-service-name", "h2-opts", "http-opts", "method",
	"reality-opts", "public-key", "short-id", "flow", "packet-encoding", "up", "down", "obfs",
	"obfs-password", "alpn", "plugin", "plugin-opts", "mode", "tfo", "mptcp", "smux", "enabled",
	"protocol", "padding", "udp-over-tcp", "udp-over-tcp-version", "username", "auth", "auth-str",
	"ports", "hop-interval", "congestion-controller", "udp-relay-mode", "reduce-rtt",
	"heartbeat-interval", "request-timeout", "disable-sni", "token", "version", "protocol-param",
	"obfs-param", "psk", "ech-opts", "xudp", "global-padding", "authenticated-length",
	"early-data-header-name", "max-early-data", "v2ray-http-upgrade", "encryption",
	"fingerprint", "interface-name", "routing-mark", "ip-version", "dialer-proxy", "fast-open",
	"max-connections", "min-streams", "max-streams", "idle-session-check-interval",
	"idle-session-timeout", "min-idle-session", "ca", "ca-str", "cwnd", "recv-window-conn",
	"recv-window", "disable-mtu-discovery", "private-key", "ip", "ipv6", "mtu", "peers",
	"allowed-ips", "reserved", "pre-shared-key", "remote-dns-resolve", "dns", "shadow-tls-opts",
	"xhttp-opts", "certificate", "benchmark-url", "benchmark-timeout", "name-cert-verify",
	"udp-over-stream", "udp-over-stream-version", "multiplexing", "transport", "key",
	"handshake-mode", "obfs-opts", "port-range", "mux", "proto", "url",
	"ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "snell",
	"socks5", "http", "wireguard", "ssh", "mieru", "sudoku", "masque", "trusttunnel",
	"shadowquic", "gost-relay", "direct", "reject", "openvpn", "auto", "none", "zero",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305", "chacha20-poly1305", "2022-blake3-aes-128-gcm",
	"2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-cfb", "aes-256-cfb",
	"aes-128-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20", "ws", "grpc", "h2",
	"tcp", "xhttp", "httpupgrade", "xtls-rprx-vision", "chrome", "firefox", "safari", "ios",
	"android", "edge", "random", "randomized", "qq", "360", "salamander", "h3", "http/1.1", "bbr",
	"cubic", "new_reno", "native", "quic", "/", "v2ray-plugin", "shadow-tls", "websocket",
	"yamux", "h2mux", "packetaddr", "origin", "plain", "auth_aes128_md5", "auth_aes128_sha1",
	"auth_chain_a", "auth_chain_b", "http_simple", "http_post", "tls1.2_ticket_auth", "simple-obfs",
	"restls", "ipv4", "ipv4-prefer", "ipv6-prefer", "dual", "packet", "stream", "both",
}

var nodeConfigIndex struct {
	once  sync.Once
	words map[string]uint64
}

func nodeConfigWord(s string) (uint64, bool) {
	nodeConfigIndex.once.Do(func() {
		words := make(map[string]uint64, len(nodeConfigWords))
		for i, word := range nodeConfigWords {
			if _, dup := words[word]; !dup {
				words[word] = uint64(i)
			}
		}
		nodeConfigIndex.words = words
	})
	i, ok := nodeConfigIndex.words[s]
	return i, ok
}

var errNodeConfigType = errors.New("node configuration: a value of a type the encoding does not keep")

type nodeConfigWriter struct {
	buf []byte
}

var nodeConfigBuffers = sync.Pool{New: func() any { return &nodeConfigWriter{buf: make([]byte, 0, 512)} }}

func encodeNodeConfig(mapping map[string]any) (config string, ok bool) {
	w := nodeConfigBuffers.Get().(*nodeConfigWriter)
	w.buf = w.buf[:0]
	err := w.value(mapping)
	if err == nil {
		config = string(w.buf)
	}
	if cap(w.buf) <= 64<<10 {
		nodeConfigBuffers.Put(w)
	}
	return config, err == nil
}

func (w *nodeConfigWriter) uvarint(v uint64) { w.buf = binary.AppendUvarint(w.buf, v) }
func (w *nodeConfigWriter) varint(v int64)   { w.buf = binary.AppendVarint(w.buf, v) }
func (w *nodeConfigWriter) tagged(tag byte)  { w.buf = append(w.buf, tag) }
func (w *nodeConfigWriter) count(n int)      { w.uvarint(uint64(n)) }

func (w *nodeConfigWriter) string(s string) {
	if index, ok := nodeConfigWord(s); ok {
		w.tagged(cfgWord)
		w.uvarint(index)
		return
	}
	if id, ok := canonicalUUID(s); ok {
		w.tagged(cfgUUID)
		w.buf = append(w.buf, id[:]...)
		return
	}
	w.tagged(cfgString)
	w.count(len(s))
	w.buf = append(w.buf, s...)
}

func (w *nodeConfigWriter) value(v any) error {
	switch v := v.(type) {
	case nil:
		w.tagged(cfgNil)
	case bool:
		if v {
			w.tagged(cfgTrue)
		} else {
			w.tagged(cfgFalse)
		}
	case string:
		w.string(v)
	case int:
		w.tagged(cfgInt)
		w.varint(int64(v))
	case int8:
		w.tagged(cfgInt8)
		w.varint(int64(v))
	case int16:
		w.tagged(cfgInt16)
		w.varint(int64(v))
	case int32:
		w.tagged(cfgInt32)
		w.varint(int64(v))
	case int64:
		w.tagged(cfgInt64)
		w.varint(v)
	case uint:
		w.tagged(cfgUint)
		w.uvarint(uint64(v))
	case uint8:
		w.tagged(cfgUint8)
		w.uvarint(uint64(v))
	case uint16:
		w.tagged(cfgUint16)
		w.uvarint(uint64(v))
	case uint32:
		w.tagged(cfgUint32)
		w.uvarint(uint64(v))
	case uint64:
		w.tagged(cfgUint64)
		w.uvarint(v)
	case float32:
		w.tagged(cfgFloat32)
		w.buf = binary.LittleEndian.AppendUint32(w.buf, math.Float32bits(v))
	case float64:
		w.tagged(cfgFloat64)
		w.buf = binary.LittleEndian.AppendUint64(w.buf, math.Float64bits(v))
	case []any:
		w.tagged(cfgList)
		w.count(len(v))
		for _, item := range v {
			if err := w.value(item); err != nil {
				return err
			}
		}
	case []string:
		w.tagged(cfgStrings)
		w.count(len(v))
		for _, item := range v {
			w.string(item)
		}
	case map[string]any:
		if v == nil {
			return errNodeConfigType
		}
		w.tagged(cfgMap)
		w.count(len(v))
		for _, key := range sortedKeys(v) {
			w.string(key)
			if err := w.value(v[key]); err != nil {
				return err
			}
		}
	case map[string]string:
		if v == nil {
			return errNodeConfigType
		}
		w.tagged(cfgStringMap)
		w.count(len(v))
		for _, key := range sortedKeys(v) {
			w.string(key)
			w.string(v[key])
		}
	case map[any]any:
		if v == nil {
			return errNodeConfigType
		}
		w.tagged(cfgAnyMap)
		w.count(len(v))
		for key, item := range v {
			if err := w.value(key); err != nil {
				return err
			}
			if err := w.value(item); err != nil {
				return err
			}
		}
	case []map[string]any:
		w.tagged(cfgMapList)
		w.count(len(v))
		for _, item := range v {
			if err := w.value(item); err != nil {
				return err
			}
		}
	default:
		return errNodeConfigType
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func canonicalUUID(s string) (id [16]byte, ok bool) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, false
	}
	j := 0
	for _, part := range [...]string{s[0:8], s[9:13], s[14:18], s[19:23], s[24:36]} {
		for k := 0; k < len(part); k += 2 {
			hi, okHi := lowerHex(part[k])
			lo, okLo := lowerHex(part[k+1])
			if !okHi || !okLo {
				return id, false
			}
			id[j] = hi<<4 | lo
			j++
		}
	}
	return id, true
}

func lowerHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func formatUUID(id []byte) string {
	var out [36]byte
	hex.Encode(out[0:8], id[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], id[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], id[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], id[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], id[10:16])
	return string(out[:])
}

var errNodeConfigCorrupt = errors.New("node configuration: corrupt encoding")

type nodeConfigReader struct {
	s string
	i int
}

func decodeNodeConfig(config string) (map[string]any, error) {
	r := nodeConfigReader{s: config}
	v, err := r.value()
	if err != nil {
		return nil, err
	}
	mapping, ok := v.(map[string]any)
	if !ok || r.i != len(r.s) {
		return nil, errNodeConfigCorrupt
	}
	return mapping, nil
}

func (r *nodeConfigReader) byte() (byte, error) {
	if r.i >= len(r.s) {
		return 0, errNodeConfigCorrupt
	}
	b := r.s[r.i]
	r.i++
	return b, nil
}

func (r *nodeConfigReader) uvarint() (uint64, error) {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, nil
		}
	}
	return 0, errNodeConfigCorrupt
}

func (r *nodeConfigReader) varint() (int64, error) {
	u, err := r.uvarint()
	v := int64(u >> 1)
	if u&1 != 0 {
		v = ^v
	}
	return v, err
}

func (r *nodeConfigReader) count() (int, error) {
	n, err := r.uvarint()
	if err != nil || n > uint64(len(r.s)-r.i) {
		return 0, errNodeConfigCorrupt
	}
	return int(n), nil
}

func (r *nodeConfigReader) take(n int) (string, error) {
	if n < 0 || n > len(r.s)-r.i {
		return "", errNodeConfigCorrupt
	}
	s := r.s[r.i : r.i+n]
	r.i += n
	return s, nil
}

func (r *nodeConfigReader) string() (string, error) {
	v, err := r.value()
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", errNodeConfigCorrupt
	}
	return s, nil
}

func (r *nodeConfigReader) value() (any, error) {
	tag, err := r.byte()
	if err != nil {
		return nil, err
	}
	switch tag {
	case cfgNil:
		return nil, nil
	case cfgFalse:
		return false, nil
	case cfgTrue:
		return true, nil
	case cfgString:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		return r.take(n)
	case cfgWord:
		index, err := r.uvarint()
		if err != nil || index >= uint64(len(nodeConfigWords)) {
			return nil, errNodeConfigCorrupt
		}
		return nodeConfigWords[index], nil
	case cfgUUID:
		s, err := r.take(16)
		if err != nil {
			return nil, err
		}
		return formatUUID([]byte(s)), nil
	case cfgInt:
		v, err := r.varint()
		return int(v), err
	case cfgInt8:
		v, err := r.varint()
		return int8(v), err
	case cfgInt16:
		v, err := r.varint()
		return int16(v), err
	case cfgInt32:
		v, err := r.varint()
		return int32(v), err
	case cfgInt64:
		return r.varint()
	case cfgUint:
		v, err := r.uvarint()
		return uint(v), err
	case cfgUint8:
		v, err := r.uvarint()
		return uint8(v), err
	case cfgUint16:
		v, err := r.uvarint()
		return uint16(v), err
	case cfgUint32:
		v, err := r.uvarint()
		return uint32(v), err
	case cfgUint64:
		return r.uvarint()
	case cfgFloat32:
		s, err := r.take(4)
		if err != nil {
			return nil, err
		}
		return math.Float32frombits(binary.LittleEndian.Uint32([]byte(s))), nil
	case cfgFloat64:
		s, err := r.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64([]byte(s))), nil
	case cfgList:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		list := make([]any, n)
		for i := range list {
			if list[i], err = r.value(); err != nil {
				return nil, err
			}
		}
		return list, nil
	case cfgStrings:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		list := make([]string, n)
		for i := range list {
			if list[i], err = r.string(); err != nil {
				return nil, err
			}
		}
		return list, nil
	case cfgMap:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			key, err := r.string()
			if err != nil {
				return nil, err
			}
			if m[key], err = r.value(); err != nil {
				return nil, err
			}
		}
		return m, nil
	case cfgStringMap:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		m := make(map[string]string, n)
		for i := 0; i < n; i++ {
			key, err := r.string()
			if err != nil {
				return nil, err
			}
			if m[key], err = r.string(); err != nil {
				return nil, err
			}
		}
		return m, nil
	case cfgAnyMap:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		m := make(map[any]any, n)
		for i := 0; i < n; i++ {
			key, err := r.value()
			if err != nil {
				return nil, err
			}
			if !comparableKey(key) {
				return nil, errNodeConfigCorrupt
			}
			if m[key], err = r.value(); err != nil {
				return nil, err
			}
		}
		return m, nil
	case cfgMapList:
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		list := make([]map[string]any, n)
		for i := range list {
			v, err := r.value()
			if err != nil {
				return nil, err
			}
			m, ok := v.(map[string]any)
			if !ok {
				return nil, errNodeConfigCorrupt
			}
			list[i] = m
		}
		return list, nil
	}
	return nil, fmt.Errorf("%w: tag %d", errNodeConfigCorrupt, tag)
}

func comparableKey(v any) bool {
	switch v.(type) {
	case []any, []string, map[string]any, map[string]string, map[any]any, []map[string]any:
		return false
	}
	return true
}
