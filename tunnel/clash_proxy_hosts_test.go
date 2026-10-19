package tunnel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	icontext "github.com/ProjectClash/Clash/context"
)

type fakeProxyHosts map[string][2]string

func (h fakeProxyHosts) SearchProxyHost(host string) ([]netip.Addr, string, bool) {
	entry, ok := h[host]
	if !ok {
		return nil, "", false
	}
	if entry[1] != "" {
		return nil, entry[1], true
	}
	return []netip.Addr{netip.MustParseAddr(entry[0])}, "", true
}

func TestProxyHostsReachOnlyAFlowToAProxy(t *testing.T) {
	hosts := fakeProxyHosts{"api.example": {"2606:4700:4700::1001", ""}, "alias.example": {"", "edge.example"}}
	node := doorProxy{name: "HK", typ: C.Shadowsocks}
	for name, tc := range map[string]struct {
		proxy      C.Proxy
		host, want string
	}{
		"a node":               {node, "api.example", "[2606:4700:4700::1001]:443"},
		"a group on a node":    {chainProxy{doorProxy{name: "G", typ: C.Selector}, node}, "api.example", "[2606:4700:4700::1001]:443"},
		"a name":               {node, "alias.example", "edge.example:443"},
		"DIRECT":               {doorProxy{name: "DIRECT", typ: C.Direct}, "api.example", "api.example:443"},
		"a group on DIRECT":    {chainProxy{doorProxy{name: "G", typ: C.Selector}, doorProxy{name: "DIRECT", typ: C.Direct}}, "api.example", "api.example:443"},
		"REJECT":               {doorProxy{name: "REJECT", typ: C.Reject}, "api.example", "api.example:443"},
		"a host with no entry": {node, "other.example", "other.example:443"},
	} {
		metadata := &C.Metadata{NetWork: C.TCP, Host: tc.host, DstPort: 443}
		got := withProxyHosts(hosts, tc.proxy, metadata, metadata)
		if got.RemoteAddress() != tc.want {
			t.Errorf("%s: the proxy is asked for %s, want %s", name, got.RemoteAddress(), tc.want)
		}
		if metadata.Host != tc.host || metadata.DstIP.IsValid() {
			t.Errorf("%s: the flow's own metadata changed to %s / %s", name, metadata.Host, metadata.DstIP)
		}
	}
	metadata := &C.Metadata{NetWork: C.TCP, Host: "api.example", DstPort: 443}
	if got := withProxyHosts(nil, node, metadata, metadata); got != metadata {
		t.Error("without proxy-hosts the dial was not the flow's")
	}
}

type capturingProxy struct {
	doorProxy
	asked chan string
}

func (p *capturingProxy) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
	p.asked <- metadata.RemoteAddress()
	return nothingConn{N.NewExtendedConn(eofConn{})}, nil
}

func (p *capturingProxy) IsL3Protocol(*C.Metadata) bool { return false }

func TestATCPFlowToAProxyAsksItForTheProxyHostsAddress(t *testing.T) {
	out := &capturingProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, asked: make(chan string, 1)}
	withVerdictTunnel(t, "out", out)
	prevRouting := loadVersion().routing
	UpdateClashRouting(C.ClashRouting{ProxyHosts: fakeProxyHosts{"api.example": {"192.0.2.77", ""}}})
	t.Cleanup(func() { UpdateClashRouting(prevRouting) })
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: "api.example", DstPort: 443, SrcIP: netip.MustParseAddr("172.19.0.2"), SrcPort: 41234}
	handleTCPConn(icontext.NewConnContext(newVerdictConn(false), metadata))
	if got := <-out.asked; got != "192.0.2.77:443" {
		t.Fatalf("the proxy was asked for %s, want 192.0.2.77:443", got)
	}
}

type writesPacketConn struct {
	nothingPacketConn
	writes    chan string
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *writesPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.writes <- addr.String()
	return len(b), nil
}

func (c *writesPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	<-c.closed
	return nil, nil, nil, io.EOF
}

func (c *writesPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

type packetProxy struct {
	doorProxy
	pc    *writesPacketConn
	asked chan string
}

func (p packetProxy) ListenPacketContext(_ context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	p.asked <- metadata.RemoteAddress()
	return p.pc, nil
}

func (p packetProxy) IsL3Protocol(*C.Metadata) bool { return false }

func TestAUDPSessionToAProxySendsEveryDestinationToItsProxyHostsAddress(t *testing.T) {
	pc := &writesPacketConn{writes: make(chan string, 8), closed: make(chan struct{})}
	t.Cleanup(func() { _ = pc.Close() })
	out := packetProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, pc: pc, asked: make(chan string, 1)}
	withVerdictTunnel(t, "out", out)
	prevRouting := loadVersion().routing
	UpdateClashRouting(C.ClashRouting{ProxyHosts: fakeProxyHosts{"api.example": {"192.0.2.77", ""}, "two.example": {"192.0.2.78", ""}, "four.example": {"192.0.2.79", ""}}})
	t.Cleanup(func() { UpdateClashRouting(prevRouting) })
	for _, flow := range []struct {
		host, ip string
		mode     C.DNSMode
		want     string
	}{
		{"api.example", "", C.DNSNormal, "192.0.2.77:443"},
		{"two.example", "", C.DNSNormal, "192.0.2.78:443"},
		{"four.example", "198.51.100.4", C.DNSMapping, "192.0.2.79:443"},
		{"three.example", "192.0.2.30", C.DNSNormal, "192.0.2.30:443"},
	} {
		metadata := tunFlowTo("192.0.2.1")
		metadata.NetWork, metadata.Host, metadata.DstIP, metadata.DNSMode = C.UDP, flow.host, netip.Addr{}, flow.mode
		if flow.ip != "" {
			metadata.DstIP = netip.MustParseAddr(flow.ip)
		}
		handleUDPConn(C.NewPacketAdapter(newReportingPacket(), metadata))
		select {
		case got := <-pc.writes:
			if got != flow.want {
				t.Errorf("%s: sent to %s, want %s", flow.host, got, flow.want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: nothing was sent", flow.host)
		}
	}
	if got := <-out.asked; got != "192.0.2.77:443" {
		t.Errorf("the session was opened for %s, want 192.0.2.77:443", got)
	}
}
