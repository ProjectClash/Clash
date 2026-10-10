package clash

import (
	"testing"
)

func TestParseConfigAcceptsEveryValueUpstreamAccepts(t *testing.T) {
	for name, proxy := range map[string]string{
		"hysteria negative stream window":    "{name: P, type: hysteria, server: 10.0.0.1, port: 443, auth-str: x, up: 10, down: 50, recv-window-conn: -1}",
		"hysteria oversized window":          "{name: P, type: hysteria, server: 10.0.0.1, port: 443, auth-str: x, up: 10, down: 50, recv-window: 4611686018427387904}",
		"tuic negative window":               "{name: P, type: tuic, server: 10.0.0.1, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: x, recv-window: -1}",
		"hysteria2 oversized initial window": "{name: P, type: hysteria2, server: 10.0.0.1, port: 443, password: x, initial-stream-receive-window: 4611686018427387904}",
		"hysteria2 tiny udp-mtu":             "{name: P, type: hysteria2, server: 10.0.0.1, port: 443, password: x, udp-mtu: 8}",
		"hysteria negative speed":            "{name: P, type: hysteria, server: 10.0.0.1, port: 443, auth-str: x, up: 10, down: 50, up-speed: -1}",
		"hysteria2 unparseable rate":         "{name: P, type: hysteria2, server: 10.0.0.1, port: 443, password: x, up: not-a-rate}",
		"mekya overflowing polling interval": "{name: P, type: vmess, server: 10.0.0.1, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, alterId: 0, cipher: auto, network: mekya, mekya-opts: {polling-interval-initial: 9223372036854775807}}",
		"kcptun negative shards":             "{name: P, type: ss, server: 10.0.0.1, port: 443, cipher: aes-128-gcm, password: x, plugin: kcptun, plugin-opts: {datashard: -1, parityshard: 3}}",
		"grpc negative ping interval":        "{name: P, type: vmess, server: 10.0.0.1, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, alterId: 0, cipher: auto, network: grpc, grpc-opts: {ping-interval: -1}}",
	} {
		t.Run(name, func(t *testing.T) {
			setupConfigPipelineTest(t)
			_, err := parseConfigForIOS("proxies:\n  - "+proxy+`
dns:
  enable: true
  nameserver: [1.1.1.1]
rules:
  - MATCH,DIRECT
`, true)
			if err != nil {
				t.Fatalf("refused a value upstream accepts: %v", err)
			}
		})
	}
}

func TestParseConfigAcceptsGlobalValuesUpstreamAccepts(t *testing.T) {
	for name, document := range map[string]string{
		"overflowing keep-alive": `
keep-alive-idle: 9223372037
dns: {enable: true, nameserver: [1.1.1.1]}
rules:
  - MATCH,DIRECT
`,
		"negative dns cache size": `
dns: {enable: true, nameserver: [1.1.1.1], cache-max-size: -1}
rules:
  - MATCH,DIRECT
`,
		"negative group interval": `
proxies:
  - {name: P, type: socks5, server: 127.0.0.1, port: 1}
proxy-groups:
  - {name: G, type: url-test, proxies: [P], interval: -1}
dns: {enable: true, nameserver: [1.1.1.1]}
rules:
  - MATCH,G
`,
	} {
		t.Run(name, func(t *testing.T) {
			setupConfigPipelineTest(t)
			if _, err := parseConfigForIOS(document, true); err != nil {
				t.Fatalf("refused a value upstream accepts: %v", err)
			}
		})
	}
}

func TestParseConfigPreservesUnmaterializedRemoteProvider(t *testing.T) {
	setupConfigPipelineTest(t)
	configuration, err := parseConfigForIOS(`
rule-providers:
  remote: {type: http, behavior: domain, url: "https://example.invalid/r.yaml"}
dns: {enable: true, nameserver: [1.1.1.1]}
rules:
  - RULE-SET,remote,REJECT
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("remote provider definition was refused: %v", err)
	}
	if _, ok := configuration.RuleProviders["remote"]; !ok {
		t.Fatal("remote provider definition was dropped instead of deferred")
	}
}
