package constant

import "net/netip"

type ClashRouting struct {
	EveryModeRules   []Rule
	UDPUnsupported   string
	STUNResponseIPv4 netip.Addr
	STUNResponseIPv6 netip.Addr
	RejectPage       bool
	BlockQUIC        string
	ProxyHosts ClashProxyHosts
}

type ClashProxyHosts interface {
	SearchProxyHost(host string) (ips []netip.Addr, name string, ok bool)
}

const (
	BlockQUICAllProxy = "all-proxy"
	BlockQUICAll      = "all"
)
