package clash

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	stdhttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

const scriptOutboundDocument = `
mode: rule
proxy-groups:
  - { name: "出口 🇯🇵", type: select, proxies: [DIRECT, REJECT] }
listeners:
  - { name: q, type: mixed, listen: 127.0.0.1, port: 0, users: [{ username: engine, password: secret }], x-clash-outbound-header: true }
  - { name: lan, type: mixed, listen: 127.0.0.1, port: 0, users: [{ username: engine, password: secret }] }
rules:
  - MATCH,REJECT
`

func withScriptOutboundCore(t *testing.T) (q, lan string, cfg *config.Config) {
	t.Helper()
	return withScriptOutboundDocument(t, scriptOutboundDocument)
}

func withScriptOutboundDocument(t *testing.T, document string) (q, lan string, cfg *config.Config) {
	t.Helper()
	cfg, err := config.Parse([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	previousProxies, previousProviders, previousStatus := tunnel.Proxies(), tunnel.Providers(), tunnel.Status()
	previousRules, previousRuleProviders := tunnel.Rules(), tunnel.RuleProviders()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.UpdateProxies(previousProxies, previousProviders)
		tunnel.UpdateRules(previousRules, nil, previousRuleProviders)
		switch previousStatus {
		case tunnel.Suspend:
			tunnel.OnSuspend()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		}
	})
	addresses := map[string]string{}
	for _, name := range []string{"q", "lan"} {
		listener := cfg.Listeners[name]
		if listener == nil {
			t.Fatalf("the document has no listener %q", name)
		}
		if err := listener.Listen(tunnel.Tunnel); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		addresses[name] = listener.Address()
	}
	return addresses["q"], addresses["lan"], cfg
}

func scriptOutboundEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func connectThrough(t *testing.T, proxy, target, outbound string, authenticate bool) (*stdhttp.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if authenticate {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("engine:secret")) + "\r\n"
	}
	if outbound != "" {
		request += "Clash-Outbound: " + outbound + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := stdhttp.ReadResponse(reader, &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s naming %q: %v", target, outbound, err)
	}
	return response, conn, reader
}

func echoes(conn net.Conn, reader *bufio.Reader) bool {
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		return false
	}
	line, err := reader.ReadString('\n')
	return err == nil && line == "ping\n"
}

func TestScriptOutboundHeaderLeavesByTheNamedOutboundOnTheReinjectListener(t *testing.T) {
	q, _, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)

	response, conn, reader := connectThrough(t, q, echo, "", true)
	if response.StatusCode == stdhttp.StatusOK && echoes(conn, reader) {
		t.Fatal("without the header the flow must follow the rules, which refuse it")
	}

	response, conn, reader = connectThrough(t, q, echo, "DIRECT", true)
	if response.StatusCode != stdhttp.StatusOK {
		t.Fatalf("a name the configuration has: status %d, want 200", response.StatusCode)
	}
	if !echoes(conn, reader) {
		t.Fatal("the flow did not leave by DIRECT, the outbound its CONNECT named")
	}
}

func TestScriptOutboundHeaderNamingAGroupFollowsItsSelection(t *testing.T) {
	q, _, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)
	name := url.PathEscape("出口 🇯🇵")

	response, conn, reader := connectThrough(t, q, echo, name, true)
	if response.StatusCode != stdhttp.StatusOK || !echoes(conn, reader) {
		t.Fatalf("the group selects DIRECT, so the flow must reach the echo server (status %d)", response.StatusCode)
	}

	group, ok := tunnel.Proxies()["出口 🇯🇵"]
	if !ok {
		t.Fatal("the group is missing from the tunnel")
	}
	selector, ok := group.Adapter().(outboundgroup.SelectAble)
	if !ok {
		t.Fatalf("the group is a %T, not a selector", group.Adapter())
	}
	if err := selector.Set("REJECT"); err != nil {
		t.Fatal(err)
	}
	response, conn, reader = connectThrough(t, q, echo, name, true)
	if response.StatusCode == stdhttp.StatusOK && echoes(conn, reader) {
		t.Fatal("the group now selects REJECT, and the flow still reached the echo server")
	}
}

func TestScriptOutboundHeaderRefusesANameTheConfigurationLacks(t *testing.T) {
	q, _, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)

	response, _, _ := connectThrough(t, q, echo, url.PathEscape("不存在 node"), true)
	if response.StatusCode != stdhttp.StatusBadGateway {
		t.Fatalf("an unknown name: status %d, want 502", response.StatusCode)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), `no outbound named "不存在 node"`) {
		t.Fatalf("the reason must name the outbound as decoded, got %q", body)
	}
}

func TestScriptOutboundHeaderRefusesAMalformedName(t *testing.T) {
	q, _, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)

	for _, value := range []string{"%E8%8A", "%zz", "%"} {
		response, _, _ := connectThrough(t, q, echo, value, true)
		if response.StatusCode != stdhttp.StatusBadRequest {
			t.Fatalf("Clash-Outbound: %s: status %d, want 400", value, response.StatusCode)
		}
	}

	conn, err := net.DialTimeout("tcp", q, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT "+echo+" HTTP/1.1\r\nHost: "+echo+"\r\nProxy-Authorization: Basic "+
		base64.StdEncoding.EncodeToString([]byte("engine:secret"))+"\r\nClash-Outbound: \r\n\r\n")
	response, err := stdhttp.ReadResponse(bufio.NewReader(conn), &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != stdhttp.StatusBadRequest {
		t.Fatalf("an empty Clash-Outbound: status %d, want 400", response.StatusCode)
	}
}

func TestScriptOutboundHeaderIsReadOnlyAfterAuthentication(t *testing.T) {
	q, _, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)

	for _, value := range []string{"DIRECT", url.PathEscape("不存在 node")} {
		response, _, _ := connectThrough(t, q, echo, value, false)
		if response.StatusCode != stdhttp.StatusProxyAuthRequired {
			t.Fatalf("an unauthenticated CONNECT naming %q: status %d, want 407", value, response.StatusCode)
		}
	}
}

func TestScriptOutboundHeaderIsIgnoredOnEveryOtherListener(t *testing.T) {
	_, lan, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)

	response, conn, reader := connectThrough(t, lan, echo, "DIRECT", true)
	if response.StatusCode == stdhttp.StatusOK && echoes(conn, reader) {
		t.Fatal("a listener without x-clash-outbound-header let the header pick DIRECT past the rules")
	}
	response, _, _ = connectThrough(t, lan, echo, url.PathEscape("不存在 node"), true)
	if response.StatusCode == stdhttp.StatusBadGateway || response.StatusCode == stdhttp.StatusBadRequest {
		t.Fatalf("a listener without x-clash-outbound-header read the header (status %d)", response.StatusCode)
	}
}

func TestScriptOutboundHeaderRecordsTheNameOnTheConnection(t *testing.T) {
	q, _, _ := withScriptOutboundCore(t)
	echo := scriptOutboundEcho(t)

	response, conn, reader := connectThrough(t, q, echo, "DIRECT", true)
	if response.StatusCode != stdhttp.StatusOK || !echoes(conn, reader) {
		t.Fatalf("status %d", response.StatusCode)
	}
	var found *C.Metadata
	deadline := time.Now().Add(5 * time.Second)
	for found == nil && time.Now().Before(deadline) {
		for _, connection := range statistic.DefaultManager.Snapshot().Connections {
			if connection.Metadata.InName == "q" && connection.Metadata.RemoteAddress() == echo {
				found = connection.Metadata
				if connection.Rule != "" {
					t.Fatalf("a named flow has no rule, got %q", connection.Rule)
				}
			}
		}
		if found == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if found == nil {
		t.Fatal("the flow is not in the connection table")
	}
	if found.SpecialProxy != "DIRECT" {
		t.Fatalf("the connection's specialProxy is %q, want DIRECT", found.SpecialProxy)
	}
}

func TestScriptOutboundHeaderIsNotForwardedToTheSite(t *testing.T) {
	q, _, _ := withScriptOutboundDocument(t, strings.Replace(scriptOutboundDocument, "MATCH,REJECT", "MATCH,DIRECT", 1))
	seen := make(chan stdhttp.Header, 1)
	site, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = site.Close() })
	go func() {
		_ = stdhttp.Serve(site, stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
			seen <- request.Header.Clone()
			_, _ = io.WriteString(writer, "ok")
		}))
	}()

	conn, err := net.DialTimeout("tcp", q, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	target := site.Addr().String()
	_, _ = io.WriteString(conn, "GET http://"+target+"/ HTTP/1.1\r\nHost: "+target+"\r\nProxy-Authorization: Basic "+
		base64.StdEncoding.EncodeToString([]byte("engine:secret"))+"\r\nClash-Outbound: DIRECT\r\nX-Kept: yes\r\n\r\n")
	response, err := stdhttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != stdhttp.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	header := <-seen
	if header.Get("X-Kept") != "yes" {
		t.Fatal("the site did not get the request's own headers")
	}
	if values, present := header["Clash-Outbound"]; present {
		t.Fatalf("the site was sent Clash-Outbound: %v", values)
	}
}
