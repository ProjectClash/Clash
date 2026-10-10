package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func mihomoVerdict(t *testing.T, configYAML string) error {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(configYAML))
	if err != nil {
		return err
	}
	_, err = config.ParseRawConfig(raw)
	return err
}

func TestPlanRefusesExactlyWhatUpstreamRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, wants string }{
		"hysteria up is not a rate": {yaml: `
proxies:
  - {name: h, type: hysteria, server: e.com, port: 443, auth-str: a, up: not-a-rate, down: 10 Mbps}
`, wants: "invaild upload speed"},
		"hysteria down is not a rate": {yaml: `
proxies:
  - {name: h, type: hysteria, server: e.com, port: 443, auth-str: a, up: 10 Mbps, down: nonsense}
`, wants: "invaild download speed"},
		"hysteria2 ports is a malformed range": {yaml: `
proxies:
  - {name: h, type: hysteria2, server: e.com, port: 443, password: p, ports: bad-range}
`, wants: "ports"},
		"hysteria2 hop-interval is a malformed range": {yaml: `
proxies:
  - {name: h, type: hysteria2, server: e.com, port: 443, password: p, ports: 1000-2000, hop-interval: bad-range}
`, wants: "hop-interval"},
		"xhttp sc-max-each-post-bytes is zero": {yaml: `
proxies:
  - name: v
    type: vless
    server: e.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts: {sc-max-each-post-bytes: "0"}
`, wants: "sc-max-each-post-bytes"},
		"xhttp sc-max-each-post-bytes will not parse": {yaml: `
proxies:
  - name: v
    type: vless
    server: e.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts: {sc-max-each-post-bytes: bad-range}
`, wants: "sc-max-each-post-bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := mihomoVerdict(t, tc.yaml); err == nil {
				t.Fatalf("mihomo ACCEPTS this input, so refusing it would be stricter than upstream, "+
					"which is the whole point of this comparison:\n%s", tc.yaml)
			}
			r := planOf(t, tc.yaml)
			for _, e := range r.Errors {
				if strings.Contains(e.Field+" "+e.Reason, tc.wants) {
					return
				}
			}
			t.Errorf("mihomo refuses this and the plan does not, so the plan promises a start that will not "+
				"happen; wanted a refusal naming %q, got %+v", tc.wants, r.Errors)
		})
	}
}

func TestPlanStillToleratesWhatUpstreamOnlyClamps(t *testing.T) {
	for name, configYAML := range map[string]string{
		"hysteria2 hop-interval below the minimum": `
proxies:
  - {name: h, type: hysteria2, server: e.com, port: 443, password: p, ports: 1000-2000, hop-interval: "1"}
`,
		"quic receive window past the maximum": `
proxies:
  - {name: h, type: hysteria2, server: e.com, port: 443, password: p, initial-stream-receive-window: 999999999999999999}
`,
		"hysteria2 udp-mtu zero": `
proxies:
  - {name: h, type: hysteria2, server: e.com, port: 443, password: p, udp-mtu: 0}
`,
		"xhttp x-padding-bytes will not parse": `
proxies:
  - name: v
    type: vless
    server: e.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts: {x-padding-bytes: bad-range}
`,
		"xhttp sc-max-buffered-posts will not parse": `
proxies:
  - name: v
    type: vless
    server: e.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: xhttp
    xhttp-opts: {sc-max-buffered-posts: bad-range}
`,
		"negative tuic max datagram size": `
proxies:
  - {name: t, type: tuic, server: e.com, port: 443, uuid: u, password: p, max-udp-relay-packet-size: -1}
`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := mihomoVerdict(t, configYAML); err != nil {
				t.Fatalf("mihomo refuses this too, so it is not evidence about clamping: %v", err)
			}
			mustNotRefuse(t, planOf(t, configYAML), name)
		})
	}
}

func TestParseConfigForIOSRejectsInvalidProxyGroupRegex(t *testing.T) {
	y := "proxies:\n  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"proxy-groups:\n  - {name: G, type: select, filter: \"([unclosed\", proxies: [n]}\n"

	raw, err := config.UnmarshalRawConfig([]byte(y))
	if err != nil {
		t.Fatalf("the document does not parse as yaml, so it tests nothing: %v", err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("mihomo no longer panics on an uncompilable proxy-group filter. " +
					"This refusal was kept because a panic inside a packet-tunnel extension takes the user's " +
					"network down with it; if upstream now handles it, ask again whether refusing is still right.")
			}
		}()
		_, _ = config.ParseRawConfig(raw)
	}()

	setupConfigPipelineTest(t)
	if _, err := parseConfigForIOS(y, true); err == nil ||
		!strings.Contains(err.Error(), "not a valid regular expression") {
		t.Fatalf("an uncompilable filter reached mihomo: %v", err)
	}
}

func TestValidateRequiresExplicitNameserverOnlyWhenTheRepairDidNotRun(t *testing.T) {
	y := "proxies:\n  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"dns:\n  enable: true\n  enhanced-mode: fake-ip\n"

	if err := mihomoVerdict(t, y); err != nil {
		t.Fatalf("mihomo refuses this, so it is not evidence that we are stricter: %v", err)
	}
	setupConfigPipelineTest(t)
	if _, err := parseConfigForIOS(y, true); err != nil {
		t.Fatalf("a dns section with no nameserver must reach the core with mihomo's defaults refilled, "+
			"not be refused: %v", err)
	}
}
