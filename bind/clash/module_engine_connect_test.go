package clash

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/hub/executor"
	"github.com/ProjectClash/Clash/tunnel"
)

const moduleEngineConnectHelperEnvironment = "CLASH_MODULE_ENGINE_CONNECT_HELPER"

func TestTheModuleEngineIsAskedForTheSniffedName(t *testing.T) {
	for mode, want := range map[string]string{
		"sniffed-host": "CONNECT app.bilibili.com:443 HTTP/1.1",
		"upstream":     "CONNECT pay.bilibili.com:443 HTTP/1.1",
		"bare-address": "CONNECT 192.0.2.10:443 HTTP/1.1",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTheModuleEngineConnectHelperProcess$")
		command.Env = append(os.Environ(), moduleEngineConnectHelperEnvironment+"="+mode)
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s: helper failed: %v\n%s", mode, err, output)
		}
		if !strings.Contains(string(output), "ENGINE-ASKED "+want) {
			t.Fatalf("%s: the engine was not asked %q:\n%s", mode, want, output)
		}
	}
}

func TestTheModuleEngineConnectHelperProcess(t *testing.T) {
	mode := os.Getenv(moduleEngineConnectHelperEnvironment)
	if mode == "" {
		t.Skip("subprocess helper")
	}
	options := testOptions(t)
	options.DisablePersistentCache = true
	if err := Setup(options); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	engine, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	asked := make(chan string, 1)
	go func() {
		conn, err := engine.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		asked <- strings.TrimSpace(line)
		_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}()
	option := ""
	if mode == "sniffed-host" || mode == "bare-address" {
		option = "\n    x-clash-connect-sniffed-host: true"
	}
	configYAML := fmt.Sprintf(`mode: rule
ipv6: false
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    TLS:
      ports: [443]
proxies:
  - name: MODULE-ENGINE
    type: http
    server: 127.0.0.1
    port: %d%s
rules:
  - DOMAIN,app.bilibili.com,MODULE-ENGINE
  - DOMAIN,pay.bilibili.com,DIRECT
  - MATCH,DIRECT
`, engine.Addr().(*net.TCPAddr).Port, option)
	configuration, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		t.Fatalf("ParseWithBytes() error = %v\n%s", err, configYAML)
	}
	executor.ApplyConfig(configuration, true)

	client, core := net.Pipe()
	defer client.Close()
	metadata := &C.Metadata{
		NetWork: C.TCP, Type: C.TUN,
		SrcIP: netip.MustParseAddr("198.18.0.2"), SrcPort: 49152,
		DstIP: netip.MustParseAddr("192.0.2.10"), DstPort: 443,
		Host: "pay.bilibili.com", DNSMode: C.DNSMapping,
	}
	if mode == "bare-address" {
		metadata.Host, metadata.DNSMode = "", C.DNSNormal
	}
	go tunnel.Tunnel.HandleTCPConn(core, metadata)
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "app.bilibili.com", InsecureSkipVerify: true}).Handshake()
	}()
	select {
	case line := <-asked:
		fmt.Println("ENGINE-ASKED " + line)
	case <-time.After(5 * time.Second):
		t.Fatal("the engine was never asked")
	}
}
