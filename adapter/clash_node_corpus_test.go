package adapter

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/common/yaml"
)

func clashMixedNodesYAML(n int) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < n; i++ {
		b.WriteString("  - ")
		b.WriteString(clashMixedNodeYAML(i))
		b.WriteString("\n")
	}
	return b.String()
}

func clashMixedNodeYAML(i int) string {
	sum := sha256.Sum256([]byte(fmt.Sprint("node-", i)))
	id := fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
	secret := base64.RawStdEncoding.EncodeToString(sum[16:28])
	realityKey := base64.RawURLEncoding.EncodeToString(sum[:32])
	switch i % 5 {
	case 0:
		return fmt.Sprintf("{name: \"HK %05d\", type: ss, server: hk%d.example.net, port: %d, cipher: aes-128-gcm, password: %q, udp: true}",
			i, i, 20000+i%5000, secret)
	case 1:
		return fmt.Sprintf("{name: \"JP %05d\", type: vmess, server: jp%d.example.net, port: 443, uuid: %s, alterId: 0, cipher: auto, udp: true, tls: true, servername: jp%d.example.net, network: ws, ws-opts: {path: /ray, headers: {Host: jp%d.example.net}}}",
			i, i, id, i, i)
	case 2:
		return fmt.Sprintf("{name: \"US %05d\", type: trojan, server: us%d.example.net, port: 443, password: %s, udp: true, sni: us%d.example.net, skip-cert-verify: false}",
			i, i, id, i)
	case 3:
		return fmt.Sprintf("{name: \"SG %05d\", type: vless, server: sg%d.example.net, port: 443, uuid: %s, network: tcp, tls: true, udp: true, flow: xtls-rprx-vision, servername: www.example.com, reality-opts: {public-key: %s, short-id: 0123abcd}, client-fingerprint: chrome}",
			i, i, id, realityKey)
	default:
		return fmt.Sprintf("{name: \"TW %05d\", type: hysteria2, server: tw%d.example.net, port: 443, password: %s, sni: tw%d.example.net, skip-cert-verify: false, up: 50 Mbps, down: 200 Mbps}",
			i, i, id, i)
	}
}

func clashMixedNode(t testing.TB, i int) map[string]any {
	t.Helper()
	var mapping map[string]any
	if err := yaml.Unmarshal([]byte(clashMixedNodeYAML(i)), &mapping); err != nil {
		t.Fatal(err)
	}
	return mapping
}

func clashMixedNodes(t testing.TB, n int) []map[string]any {
	t.Helper()
	var schema struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(clashMixedNodesYAML(n)), &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Proxies) != n {
		t.Fatalf("corpus: %d nodes, want %d", len(schema.Proxies), n)
	}
	return schema.Proxies
}
