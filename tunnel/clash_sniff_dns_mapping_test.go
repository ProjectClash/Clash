package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	icontext "github.com/ProjectClash/Clash/context"
)

func clientHelloFor(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	record := make([]byte, 16384)
	n, err := server.Read(record)
	if err != nil {
		t.Fatal(err)
	}
	return record[:n]
}

func dnsMappedFlowTo(dst, name string) *C.Metadata {
	metadata := tunFlowTo(dst)
	metadata.Host = name
	metadata.DNSMode = C.DNSMapping
	return metadata
}

func TestADNSMappedIPv4FlowIsReadAndTakesItsOwnNamesRule(t *testing.T) {
	events := &eventLog{}
	engine := &dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}, dial: func() (C.Conn, error) {
		events.add("dialled MODULE-ENGINE")
		return nil, errRefused
	}}
	direct := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) {
		events.add("dialled DIRECT")
		return nil, errRefused
	}}
	withRules(t, map[string]C.Proxy{"DIRECT": direct, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine},
		[3]string{"DOMAIN", "app.bilibili.com", "MODULE-ENGINE"},
		[3]string{"DOMAIN", "pay.bilibili.com", "DIRECT"},
		[3]string{"MATCH", "", "DIRECT"},
	)
	withSniffer(t, true)
	conn := newVerdictConn(true)
	conn.events = events
	conn.payload <- clientHelloFor(t, "app.bilibili.com")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handleTCPConnContext(ctx, icontext.NewConnContext(conn, dnsMappedFlowTo("192.0.2.10", "pay.bilibili.com")))
	if got := events.all(); len(got) < 2 || got[0] != "answered-by-a-read" || got[1] != "dialled MODULE-ENGINE" {
		t.Fatalf("a DNS-mapped flow whose ClientHello names app.bilibili.com went %q, want read first and then the app's rule", got)
	}
}

func TestTheSnifferStandsAsideForADNSMappedGlobalIPv6FlowDialledPhysically(t *testing.T) {
	events := &eventLog{}
	proxy := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) {
		events.add("dialled")
		return nil, errRefused
	}}
	withVerdictTunnel(t, "DIRECT", proxy)
	withSniffer(t, true)
	conn := newVerdictConn(true)
	conn.events = events
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	handleTCPConnContext(ctx, icontext.NewConnContext(conn, dnsMappedFlowTo("2001:db8::10", "pay.bilibili.com")))
	if got := events.all(); len(got) == 0 || got[0] != "dialled" {
		t.Fatalf("want the dial first, got %q", got)
	}
}

func TestOnlyForceDNSMappingMakesTheSnifferStandAsideForAMappedIPv6Flow(t *testing.T) {
	for _, tc := range []struct {
		name            string
		forceDnsMapping bool
		forceDomains    []string
		wantFirst       string
	}{
		{"force-dns-mapping on", true, nil, "dialled"},
		{"force-dns-mapping on, force-domain names it", true, []string{"pay.bilibili.com"}, "answered-by-a-read"},
		{"force-dns-mapping off, force-domain names it", false, []string{"pay.bilibili.com"}, "answered-by-a-read"},
		{"force-dns-mapping off", false, nil, "dialled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := &eventLog{}
			proxy := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) {
				events.add("dialled")
				return nil, errRefused
			}}
			withVerdictTunnel(t, "DIRECT", proxy)
			withSniffer(t, tc.forceDnsMapping, tc.forceDomains...)
			conn := newVerdictConn(true)
			conn.events = events
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			handleTCPConnContext(ctx, icontext.NewConnContext(conn, dnsMappedFlowTo("2001:db8::10", "pay.bilibili.com")))
			if got := events.all(); len(got) == 0 || got[0] != tc.wantFirst {
				t.Fatalf("want %q first, got %q", tc.wantFirst, got)
			}
		})
	}
	withVerdictTunnel(t, "DIRECT", &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) { return nil, errRefused }})
	if !snifferStandsAside(newVerdictConn(true), tunFlowTo("2001:db8::10"), newTestSniffer(t, false)) {
		t.Fatal("the sniffer read a bare global-IPv6 flow before its dial")
	}
}
