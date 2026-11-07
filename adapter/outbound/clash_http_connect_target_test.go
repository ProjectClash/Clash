package outbound

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestAProxyThatAsksForTheSniffedNameConnectsToIt(t *testing.T) {
	mapped := func() *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Host: "pay.bilibili.com", SniffHost: "app.bilibili.com",
			DNSMode: C.DNSNormal, DstIP: netip.MustParseAddr("192.0.2.10"), DstPort: 443}
	}
	for _, tc := range []struct {
		name     string
		sniffed  bool
		metadata *C.Metadata
		want     string
	}{
		{"asks for the sniffed name", true, mapped(), "app.bilibili.com:443"},
		{"upstream's", false, mapped(), "pay.bilibili.com:443"},
		{"nothing sniffed", true, func() *C.Metadata { m := mapped(); m.SniffHost = ""; return m }(), "pay.bilibili.com:443"},
		{"a bare address the sniffer named", true, func() *C.Metadata { m := mapped(); m.Host = ""; return m }(), "192.0.2.10:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := NewHttp(HttpOption{Name: "engine", Server: "127.0.0.1", Port: 1, ClashConnectSniffedHost: tc.sniffed})
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			line := make(chan string, 1)
			go func() {
				request, _ := bufio.NewReader(server).ReadString('\n')
				line <- strings.TrimSpace(request)
				_, _ = server.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			}()
			_ = proxy.shakeHandContext(context.Background(), client, tc.metadata)
			if got := <-line; got != "CONNECT "+tc.want+" HTTP/1.1" {
				t.Fatalf("the proxy was asked %q, want CONNECT %s", got, tc.want)
			}
		})
	}
}

func TestTheSniffedHostMarkIsReadFromTheMapping(t *testing.T) {
	for value, want := range map[any]bool{true: true, false: false, "true": true, "1": true, "no": false, 1: false} {
		if got := ClashConnectsSniffedHost(map[string]any{"x-clash-connect-sniffed-host": value}); got != want {
			t.Errorf("x-clash-connect-sniffed-host: %#v reads %v, want %v", value, got, want)
		}
	}
	if ClashConnectsSniffedHost(map[string]any{"name": "engine"}) {
		t.Error("a mapping without the mark reads as marked")
	}
}
