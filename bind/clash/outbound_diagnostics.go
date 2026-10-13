package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

func (s *BoxService) outboundEndpointKindsLocked() (map[string]string, int) {
	if !s.running {
		return nil, 0
	}
	return outboundEndpointKinds(tunnel.Proxies(), tunnel.ProxyLibrary())
}

var builtinProxyNames = [...]string{"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE"}

const endpointKindsNodeLimit = 1000

func outboundEndpointKinds(proxies map[string]C.Proxy, library C.ProxyList) (kinds map[string]string, unnamed int) {
	nodes := 0
	for name, proxy := range proxies {
		if isEndpointNode(name, proxy) {
			nodes++
		}
	}
	if library != nil {
		nodes += library.Len()
	}
	if nodes > endpointKindsNodeLimit {
		return map[string]string{}, nodes
	}
	kinds = make(map[string]string, nodes)
	add := func(name string, proxy C.Proxy) {
		host := proxy.Addr()
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		kinds[anonymizedNodeID(name, proxy.Type().String())] = endpointKind(host)
	}
	for name, proxy := range proxies {
		if isEndpointNode(name, proxy) {
			add(name, proxy)
		}
	}
	if library != nil {
		for i := 0; i < library.Len(); i++ {
			node := library.At(i)
			add(node.Name(), node)
		}
	}
	return kinds, 0
}

func isEndpointNode(name string, proxy C.Proxy) bool {
	if slices.Contains(builtinProxyNames[:], name) {
		return false
	}
	_, group := proxy.Adapter().(outboundgroup.ProxyGroup)
	return !group
}

func anonymizedNodeID(name, protocolType string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(protocolType) + "\x00" + name))
	return hex.EncodeToString(digest[:8])
}

func endpointKind(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return "unknown"
	}
	if address, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		if address.Is4() {
			return "ipv4"
		}
		return "ipv6"
	}
	return "hostname"
}
