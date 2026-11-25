package statistic_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	_ "github.com/ProjectClash/Clash/hub/executor"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const gh14Config = `
proxies:
  - name: "🇨🇳 直连 | 双栈"
    type: direct
  - name: "🇨🇳 直连 | IPv4优先"
    type: direct
    ip-version: ipv4-prefer
  - name: "🇨🇳 直连 | IPv6优先"
    type: direct
    ip-version: ipv6-prefer
  - name: "🇨🇳 直连 | 仅IPv4"
    type: direct
    ip-version: ipv4
  - name: "🇨🇳 直连 | 仅IPv6"
    type: direct
    ip-version: ipv6

proxy-groups:
  - name: "直连"
    type: select
    proxies:
      - "🇨🇳 直连 | 双栈"
      - "🇨🇳 直连 | IPv4优先"
      - "🇨🇳 直连 | IPv6优先"
      - "🇨🇳 直连 | 仅IPv4"
      - "🇨🇳 直连 | 仅IPv6"

rules:
  - MATCH,直连
`

func gh14Group(t *testing.T) C.Proxy {
	t.Helper()
	disableIPv6 := resolver.DisableIPv6
	resolver.DisableIPv6 = false
	t.Cleanup(func() { resolver.DisableIPv6 = disableIPv6 })
	cfg, err := config.Parse([]byte(gh14Config))
	if err != nil {
		t.Fatalf("parse the reporter's configuration: %v", err)
	}
	group, ok := cfg.Proxies["直连"]
	if !ok {
		t.Fatal("the group 直连 is missing from the parsed configuration")
	}
	return group
}

func gh14Loopback(node string) netip.Addr {
	if node == "🇨🇳 直连 | 仅IPv6" {
		return netip.IPv6Loopback()
	}
	return netip.MustParseAddr("127.0.0.1")
}

var gh14Nodes = []string{
	"🇨🇳 直连 | 双栈",
	"🇨🇳 直连 | IPv4优先",
	"🇨🇳 直连 | IPv6优先",
	"🇨🇳 直连 | 仅IPv4",
	"🇨🇳 直连 | 仅IPv6",
}

func TestCustomNamedDirectOutboundTCPIsCountedAsDirect(t *testing.T) {
	group := gh14Group(t)
	for _, node := range gh14Nodes {
		t.Run(node, func(t *testing.T) {
			if err := group.Adapter().(outboundgroup.SelectAble).Set(node); err != nil {
				t.Fatalf("select %s: %v", node, err)
			}
			listener, err := net.Listen("tcp", net.JoinHostPort(gh14Loopback(node).String(), "0"))
			if err != nil {
				t.Skipf("no loopback for %s on this machine: %v", node, err)
			}
			defer listener.Close()
			go func() {
				server, err := listener.Accept()
				if err != nil {
					return
				}
				defer server.Close()
				_, _ = server.Write([]byte("answer"))
				_, _ = io.Copy(io.Discard, server)
			}()

			destination := listener.Addr().(*net.TCPAddr).AddrPort()
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: destination.Addr(), DstPort: destination.Port()}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := group.DialContext(ctx, metadata)
			if err != nil {
				t.Fatalf("dial through %s: %v", node, err)
			}
			if got := conn.Chains().Last(); got != node {
				t.Fatalf("final outbound = %q, want %q", got, node)
			}

			m := statistic.NewManagerForTest()
			tracked := statistic.NewTCPTracker(conn, m, metadata, nil, 0, 0, true)
			defer tracked.Close()
			if _, err := tracked.Write([]byte("question")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buffer := make([]byte, len("answer"))
			if _, err := io.ReadFull(tracked, buffer); err != nil {
				t.Fatalf("read: %v", err)
			}

			assertCountedAsDirect(t, m, int64(len("question")), int64(len("answer")))
		})
	}
}

func TestCustomNamedDirectOutboundUDPIsCountedAsDirect(t *testing.T) {
	group := gh14Group(t)
	for _, node := range gh14Nodes {
		t.Run(node, func(t *testing.T) {
			if err := group.Adapter().(outboundgroup.SelectAble).Set(node); err != nil {
				t.Fatalf("select %s: %v", node, err)
			}
			server, err := net.ListenPacket("udp", net.JoinHostPort(gh14Loopback(node).String(), "0"))
			if err != nil {
				t.Skipf("no loopback for %s on this machine: %v", node, err)
			}
			defer server.Close()
			go func() {
				buffer := make([]byte, 64)
				n, from, err := server.ReadFrom(buffer)
				if err != nil || n == 0 {
					return
				}
				_, _ = server.WriteTo([]byte("answer"), from)
			}()

			destination := server.LocalAddr().(*net.UDPAddr).AddrPort()
			metadata := &C.Metadata{NetWork: C.UDP, DstIP: destination.Addr(), DstPort: destination.Port()}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := group.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatalf("listen through %s: %v", node, err)
			}
			if got := pc.Chains().Last(); got != node {
				t.Fatalf("final outbound = %q, want %q", got, node)
			}

			m := statistic.NewManagerForTest()
			tracked := statistic.NewUDPTracker(pc, m, metadata, nil, 0, 0, true)
			defer tracked.Close()
			if _, err := tracked.WriteTo([]byte("question"), net.UDPAddrFromAddrPort(destination)); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = tracked.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 64)
			if _, _, err := tracked.ReadFrom(buffer); err != nil {
				t.Fatalf("read: %v", err)
			}

			assertCountedAsDirect(t, m, int64(len("question")), int64(len("answer")))
		})
	}
}

func assertCountedAsDirect(t *testing.T, m *statistic.Manager, up, down int64) {
	t.Helper()
	totals := m.OutboundTotals()
	if totals.Proxy.Up != 0 || totals.Proxy.Down != 0 {
		t.Errorf("proxy bucket = %d/%d, want 0/0 (a type: direct outbound is not proxy traffic)", totals.Proxy.Up, totals.Proxy.Down)
	}
	if totals.Direct.Up != up || totals.Direct.Down != down {
		t.Errorf("direct bucket = %d/%d, want %d/%d", totals.Direct.Up, totals.Direct.Down, up, down)
	}
	if proxyUp, proxyDown := m.TotalTraffic(true); proxyUp != 0 || proxyDown != 0 {
		t.Errorf("only-proxy total = %d/%d, want 0/0", proxyUp, proxyDown)
	}
}

func TestCustomNamedRejectOutboundIsCountedAsReject(t *testing.T) {
	cfg, err := config.Parse([]byte(`
proxies:
  - name: "广告拦截"
    type: reject
proxy-groups:
  - name: "拦截"
    type: select
    proxies: ["广告拦截"]
rules:
  - MATCH,拦截
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
	conn, err := cfg.Proxies["拦截"].DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	m := statistic.NewManagerForTest()
	tracked := statistic.NewTCPTracker(conn, m, metadata, nil, 0, 0, true)
	defer tracked.Close()
	if totals := m.OutboundTotals(); totals.Opened != 1 || totals.Rejected != 1 {
		t.Fatalf("opened=%d rejected=%d, want 1/1", totals.Opened, totals.Rejected)
	}
}

func TestProxyNodeOverADirectDialerProxyIsCountedAsProxy(t *testing.T) {
	group := gh14Group(t)
	if err := group.Adapter().(outboundgroup.SelectAble).Set("🇨🇳 直连 | 双栈"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		server, err := listener.Accept()
		if err != nil {
			return
		}
		defer server.Close()
		_, _ = io.Copy(io.Discard, server)
	}()
	destination := listener.Addr().(*net.TCPAddr).AddrPort()
	innerMetadata := &C.Metadata{Type: C.INNER, NetWork: C.TCP, DstIP: destination.Addr(), DstPort: destination.Port()}
	inner, err := group.DialContext(context.Background(), innerMetadata)
	if err != nil {
		t.Fatalf("dial the inner hop: %v", err)
	}
	m := statistic.NewManagerForTest()
	innerTracked := statistic.NewTCPTracker(inner, m, innerMetadata, nil, 0, 0, false)

	node, err := outbound.NewHttp(outbound.HttpOption{
		BasicOption: outbound.BasicOption{DialerProxy: "直连"},
		Name:        "my-http", Server: destination.Addr().String(), Port: int(destination.Port()),
	})
	if err != nil {
		t.Fatal(err)
	}
	outer := outbound.NewConn(innerTracked, node)
	metadata := &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 443}
	tracked := statistic.NewTCPTracker(outer, m, metadata, nil, 0, 0, true)
	defer tracked.Close()
	if _, err := tracked.Write([]byte("question")); err != nil {
		t.Fatalf("write: %v", err)
	}
	totals := m.OutboundTotals()
	if totals.Proxy.Up != int64(len("question")) || totals.Direct.Up != 0 {
		t.Fatalf("proxy up=%d direct up=%d, want %d/0", totals.Proxy.Up, totals.Direct.Up, len("question"))
	}
}

func TestDnsOutboundIsCountedAsDirect(t *testing.T) {
	cfg, err := config.Parse([]byte(`
proxies:
  - name: "dns-out"
    type: dns
proxy-groups:
  - name: "解析"
    type: select
    proxies: ["dns-out"]
rules:
  - MATCH,解析
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	group := cfg.Proxies["解析"]
	metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53}
	conn, err := group.DialContext(context.Background(), metadata)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := statistic.BucketForConnection(conn); got != statistic.BucketDirect {
		t.Errorf("TCP bucket = %d, want direct (%d)", got, statistic.BucketDirect)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udpMetadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53}
	pc, err := group.ListenPacketContext(ctx, udpMetadata)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	if got := statistic.BucketForConnection(pc); got != statistic.BucketDirect {
		t.Errorf("UDP bucket = %d, want direct (%d)", got, statistic.BucketDirect)
	}
}

type opaqueConn struct{ C.Conn }

func TestAConnectionThatDoesNotReachItsOutboundIsCountedByNameAndSaysSo(t *testing.T) {
	statistic.ForgetEgressFallbackNoteForTest()
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)

	client, server := net.Pipe()
	defer server.Close()
	direct := outbound.NewDirectWithOption(outbound.DirectOption{Name: "my-direct"})
	conn := opaqueConn{outbound.NewConn(client, direct)}
	defer conn.Close()
	if got := statistic.BucketForConnection(conn); got != statistic.BucketProxy {
		t.Fatalf("bucket = %d, want proxy (%d): by name, as before", got, statistic.BucketProxy)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case event := <-sub:
			if event.LogLevel == log.DEBUG && strings.Contains(event.Payload, "my-direct") && strings.Contains(event.Payload, "by name") {
				return
			}
		case <-deadline:
			t.Fatal("no debug line names the connection counted by name")
		}
	}
}
