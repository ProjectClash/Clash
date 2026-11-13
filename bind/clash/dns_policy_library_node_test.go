package clash

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/transport/socks5"
	D "github.com/miekg/dns"
)

const (
	libraryPolicyDomain     = "internal.example.test"
	libraryPolicyNameserver = "192.0.2.53:53"
)

func TestPolicyNameserverGoesThroughTheNodeItNames(t *testing.T) {
	node := startPolicyViaNode(t)
	for _, test := range []struct {
		name    string
		scheme  string
		named   bool
		library bool
	}{
		{"tcp named, as the command-line core runs it", "tcp", true, false},
		{"udp named, as the command-line core runs it", "udp", true, false},
		{"tcp named, published by the App", "tcp", true, true},
		{"udp named, published by the App", "udp", true, true},
		{"tcp by respect-rules, published by the App", "tcp", false, true},
		{"udp by respect-rules, published by the App", "udp", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			startPolicyNameserverCore(t, policyNameserverYAML(node.port, test.scheme, test.named), test.library)
			before := node.seenCount(test.scheme)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			msg := new(D.Msg)
			msg.SetQuestion(libraryPolicyDomain+".", D.TypeA)
			answer, err := resolver.DefaultResolver.ExchangeContext(ctx, msg)
			if err != nil {
				t.Fatalf("the policy's nameserver gave no answer: %v (node saw %v)", err, node.seenList())
			}
			if len(answer.Answer) != 1 || answer.Answer[0].(*D.A).A.String() != "192.0.2.10" {
				t.Fatalf("answer = %v, want the controlled resolver's 192.0.2.10", answer.Answer)
			}
			if node.seenCount(test.scheme) == before {
				t.Fatalf("the node never carried a %s query to %s (saw %v)", test.scheme, libraryPolicyNameserver, node.seenList())
			}
		})
	}
}

func policyNameserverYAML(nodePort int, scheme string, named bool) string {
	nameserver := scheme + "://" + libraryPolicyNameserver
	respectRules := "true"
	if named {
		nameserver += "#via"
		respectRules = "false"
	}
	return fmt.Sprintf(`
mode: rule
log-level: debug
dns:
  enable: true
  listen: ""
  ipv6: false
  enhanced-mode: redir-host
  respect-rules: %s
  default-nameserver: [192.0.2.1]
  proxy-server-nameserver: [192.0.2.1]
  nameserver: [192.0.2.1]
  nameserver-policy:
    %q: %q
proxies:
  - {name: via, type: socks5, server: 127.0.0.1, port: %d, udp: true}
proxy-groups:
  - {name: PROXY, type: select, proxies: [via, DIRECT]}
rules:
  - IP-CIDR,192.0.2.53/32,via,no-resolve
  - MATCH,DIRECT
`, respectRules, libraryPolicyDomain, nameserver, nodePort)
}

func startPolicyNameserverCore(t *testing.T, document string, library bool) {
	t.Helper()
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if library {
		resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
		finalized, err := FinalizeForIOS(document, string(resources))
		if err != nil {
			t.Fatalf("FinalizeForIOS: %v", err)
		}
		if !strings.Contains(finalized.Value, "x-clash-node-library") {
			t.Fatalf("the published configuration holds its node inline, not in a library:\n%s", finalized.Value)
		}
		document = finalized.Value
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(document); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

type policyViaNode struct {
	port int
	mu   sync.Mutex
	seen []string
}

func (n *policyViaNode) record(entry string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.seen = append(n.seen, entry)
}

func (n *policyViaNode) seenList() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.seen...)
}

func (n *policyViaNode) seenCount(network string) int {
	count := 0
	for _, entry := range n.seenList() {
		if entry == network+" "+libraryPolicyNameserver {
			count++
		}
	}
	return count
}

func startPolicyViaNode(t *testing.T) *policyViaNode {
	t.Helper()
	reach := map[string]string{}
	for _, transport := range []string{"tcp", "udp"} {
		server, address, observed := startControlledDNSServer(t, transport)
		t.Cleanup(func() { _ = server.Shutdown() })
		done := make(chan struct{})
		t.Cleanup(func() { close(done) })
		go func() {
			for {
				select {
				case <-observed:
				case <-done:
					return
				}
			}
		}()
		reach[transport] = address
	}

	var listener net.Listener
	var relay net.PacketConn
	for attempt := 0; relay == nil; attempt++ {
		if attempt == 20 {
			t.Fatal("no port free for both TCP and UDP")
		}
		var err error
		if listener, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if relay, err = net.ListenPacket("udp4", listener.Addr().String()); err != nil {
			_ = listener.Close()
			relay = nil
		}
	}
	t.Cleanup(func() { _ = listener.Close(); _ = relay.Close() })
	node := &policyViaNode{port: listener.Addr().(*net.TCPAddr).Port}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				target, command, _, err := socks5.ServerHandshake(conn, nil)
				if err != nil {
					return
				}
				if command == socks5.CmdUDPAssociate {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				node.record("tcp " + target.String())
				if target.String() != libraryPolicyNameserver {
					return
				}
				upstream, err := net.Dial("tcp", reach["tcp"])
				if err != nil {
					return
				}
				defer upstream.Close()
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, from, err := relay.ReadFrom(buffer)
			if err != nil {
				return
			}
			target, payload, err := socks5.DecodeUDPPacket(append([]byte(nil), buffer[:n]...))
			if err != nil {
				continue
			}
			node.record("udp " + target.String())
			if target.String() != libraryPolicyNameserver {
				continue
			}
			go func() {
				upstream, err := net.Dial("udp", reach["udp"])
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := upstream.Write(payload); err != nil {
					return
				}
				reply := make([]byte, 65535)
				m, err := upstream.Read(reply)
				if err != nil {
					return
				}
				if packet, err := socks5.EncodeUDPPacket(target, reply[:m]); err == nil {
					_, _ = relay.WriteTo(packet, from)
				}
			}()
		}
	}()
	return node
}

func TestAFragmentNamingALibrarysNodeIsNotReportedUnroutable(t *testing.T) {
	document := strings.Replace(policyNameserverYAML(1080, "udp", true),
		"\n  nameserver: [192.0.2.1]", "\n  nameserver: [\"udp://192.0.2.1#nowhere\"]", 1)
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	if !strings.Contains(finalized.Value, "x-clash-node-library") {
		t.Fatalf("the published configuration holds its node inline, not in a library:\n%s", finalized.Value)
	}
	lines := fragmentWarnings(t, func() {
		if _, err := parseConfigForIOS(finalized.Value, true); err != nil {
			t.Fatalf("parse: %v", err)
		}
	})
	if len(lines) != 1 || !strings.Contains(lines[0], "#nowhere") {
		t.Fatalf("warned %q, want the one fragment naming nothing (#nowhere) and not the library's node (#via)", lines)
	}
}

func TestOnlyTheExtensionsParseWarnsOfAnUnroutableFragment(t *testing.T) {
	document := strings.Replace(policyNameserverYAML(1080, "udp", true),
		"\n  nameserver: [192.0.2.1]", "\n  nameserver: [\"udp://192.0.2.1#nowhere\"]", 1)
	for _, underNE := range []bool{false, true} {
		lines := fragmentWarnings(t, func() {
			if _, err := parseConfigForIOS(document, underNE); err != nil {
				t.Fatalf("parse (underNE=%v): %v", underNE, err)
			}
		})
		if want := map[bool]int{false: 0, true: 1}[underNE]; len(lines) != want {
			t.Fatalf("underNE=%v warned %q, want %d warning(s)", underNE, lines, want)
		}
	}
}

func TestThePlanOfAPublishedConfigurationKnowsItsLibrarysNodes(t *testing.T) {
	document := strings.Replace(policyNameserverYAML(1080, "udp", true),
		"\n  nameserver: [192.0.2.1]", "\n  nameserver: [\"udp://192.0.2.1#nowhere\"]", 1)
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatalf("FinalizeForIOS: %v", err)
	}
	r := planOf(t, finalized.Value)
	var fragments []string
	for _, notice := range r.Notices {
		if strings.Contains(notice, "fragment names") {
			fragments = append(fragments, notice)
		}
	}
	if len(fragments) != 1 || !strings.Contains(fragments[0], "#nowhere") {
		t.Fatalf("plan noted %q, want the one fragment naming nothing (#nowhere) and not the library's node (#via)", fragments)
	}
}

func fragmentWarnings(t *testing.T, action func()) []string {
	t.Helper()
	subscription := log.Subscribe()
	defer log.UnSubscribe(subscription)
	const done = "dns-fragment-warnings-collected"
	warned := make(chan []string, 1)
	go func() {
		var lines []string
		for event := range subscription {
			if event.Payload == done {
				warned <- lines
				return
			}
			if strings.Contains(event.Payload, "names a physical interface or an unknown proxy") {
				lines = append(lines, event.Payload)
			}
		}
	}()
	action()
	log.Infoln(done)
	select {
	case lines := <-warned:
		return lines
	case <-time.After(5 * time.Second):
		t.Fatal("the log stream did not drain")
		return nil
	}
}
