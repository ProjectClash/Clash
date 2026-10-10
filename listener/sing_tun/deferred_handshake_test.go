package sing_tun

import (
	"net/netip"
	"testing"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	tun "github.com/metacubex/sing-tun"

	mihomoN "github.com/ProjectClash/Clash/common/net"
)

func TestListenerHandlerIsADeferredHandshakeHandler(t *testing.T) {
	var _ tun.DeferredHandshakeHandler = (*ListenerHandler)(nil)
}

func TestTheTwoHalvesOfTheContractStillMatch(t *testing.T) {
	var _ mihomoN.DeferredHandshakeConn = (tun.DeferredHandshakeConn)(nil)
	var _ tun.DeferredHandshakeConn = (mihomoN.DeferredHandshakeConn)(nil)
}

func TestDeferHandshakeScope(t *testing.T) {
	h := &ListenerHandler{}
	src4 := M.SocksaddrFrom(netip.MustParseAddr("172.19.0.2"), 40000)
	src6 := M.SocksaddrFrom(netip.MustParseAddr("fdfe:dcba:9876::2"), 40000)
	for _, tc := range []struct {
		name    string
		network string
		src     M.Socksaddr
		dst     string
		want    bool
		why     string
	}{
		{"IPv4", N.NetworkTCP, src4, "203.0.113.88", true, "a dial that fails must reach the app as a reset"},
		{"global IPv6", N.NetworkTCP, src6, "2001:db8:57::5", true, "the same answer as IPv4"},
		{"NAT64", N.NetworkTCP, src6, "64:ff9b::808:808", true, "a translated destination can fail to dial like any other"},
		{"ULA", N.NetworkTCP, src6, "fd00::1", true, "the dial decides, not the address class"},
		{"fake-ip", N.NetworkTCP, src4, "198.18.0.7", true, "resolved inside the tunnel, but still dialled"},
		{"UDP", N.NetworkUDP, src6, "2001:db8:57::5", false, "there is no handshake to hold back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := M.SocksaddrFrom(netip.MustParseAddr(tc.dst), 443)
			if got := h.DeferHandshake(tc.network, tc.src, dst); got != tc.want {
				t.Fatalf("DeferHandshake(%s, %s) = %v, want %v: %s", tc.network, tc.dst, got, tc.want, tc.why)
			}
		})
	}
}

func TestTheTunnelsOwnAddressesAreNotDeferred(t *testing.T) {
	h := &ListenerHandler{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("2001:db8:1234::/64")},
	}
	for _, addr := range []string{"172.19.0.1", "2001:db8:1234::5"} {
		dst := M.SocksaddrFrom(netip.MustParseAddr(addr), 443)
		if h.DeferHandshake(N.NetworkTCP, M.Socksaddr{}, dst) {
			t.Fatalf("%s: a flow to the tunnel itself has no dial to wait for", addr)
		}
	}
}

func TestAHijackedDNSQueryIsNotDeferred(t *testing.T) {
	h := &ListenerHandler{DnsAddrPorts: []netip.AddrPort{
		netip.MustParseAddrPort("0.0.0.0:53"),
		netip.MustParseAddrPort("[::]:53"),
	}}
	for _, addr := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		query := M.SocksaddrFrom(netip.MustParseAddr(addr), 53)
		if !h.ShouldHijackDns(query.AddrPort()) {
			t.Fatalf("setup: the wildcard listener takes %s", query)
		}
		if h.DeferHandshake(N.NetworkTCP, M.Socksaddr{}, query) {
			t.Fatalf("%s is hijacked, so the tunnel answers it itself", query)
		}
		if !h.DeferHandshake(N.NetworkTCP, M.Socksaddr{}, M.SocksaddrFrom(query.Addr, 443)) {
			t.Fatalf("port 443 to %s is not hijacked and waits for its dial", addr)
		}
	}
}
