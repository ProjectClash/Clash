package clash

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/common/convert"
	"go.yaml.in/yaml/v3"
)

func TestThisTreeNeverRefusesAShareLinkUpstreamAccepts(t *testing.T) {
	bases := map[string]string{
		"ss":        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080#N",
		"trojan":    "trojan://pw@e.example:443#N",
		"vless":     "vless://11111111-1111-1111-1111-111111111111@e.example:443#N",
		"vmess":     "vmess://11111111-1111-1111-1111-111111111111@e.example:443#N",
		"anytls":    "anytls://pw@e.example:443#N",
		"hysteria2": "hysteria2://pw@e.example:443#N",
		"tuic":      "tuic://11111111-1111-1111-1111-111111111111:pw@e.example:443#N",
		"socks5":    "socks5://dXNlcjpwYXNz@e.example:1080#N",
		"http":      "http://dXNlcjpwYXNz@e.example:8080#N",
		"hysteria":  "hysteria://e.example:443?auth=pw&up=50&down=100#N",
	}
	values := map[string]string{
		"udp": "1", "uot": "1", "udp-over-tcp": "true", "tfo": "1", "fastopen": "1",
		"sni": "p.example", "peer": "p.example", "serverName": "p.example", "tlsServerName": "p.example",
		"alpn": "h2", "fingerprint": "chrome", "fp": "chrome", "client-fingerprint": "chrome",
		"hpkp": "aa", "pinSHA256": "aa", "skip-cert-verify": "1", "insecure": "1",
		"allowInsecure": "1", "allow_insecure": "1", "tls": "1", "xtls": "1", "security": "tls",
		"keepalive": "10", "reuse": "1", "version": "4", "psk": "cHNr", "password": "pw",
		"pbk": "aaaa", "publicKey": "aaaa", "sid": "ab", "shortId": "ab", "pcs": "1",
		"up": "50", "upmbps": "50", "down": "100", "downmbps": "100", "auth": "pw",
		"obfs": "salamander", "obfs-password": "opw", "obfsParam": "op", "protocol": "udp",
		"type": "ws", "headerType": "none", "host": "h.example", "path": "/p", "mode": "gun",
		"serviceName": "svc", "ed": "2048", "eh": "X", "extra": "{}", "flow": "xtls-rprx-vision",
		"encryption": "none", "packetEncoding": "packetaddr", "padding": "1", "fragment": "1",
		"alterId": "0", "method": "GET", "title": "T", "remark": "R", "remarks": "R", "name": "N",
		"ports": "443-444", "mport": "443-444", "hop-interval": "30", "hopInterval": "30",
		"stun": "s.example:3478", "disable_sni": "1", "congestion_control": "bbr",
		"congestion-controller": "bbr", "udp_relay_mode": "quic", "udp-relay-mode": "quic",
		"proto": "udp", "network": "ws", "obfs-mode": "http", "obfs-host": "h.example",
	}
	schemes := make([]string, 0, len(bases))
	for scheme := range bases {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)

	var probed int
	for _, scheme := range schemes {
		base := bases[scheme]
		if converted, err := convert.ConvertsV2Ray([]byte(base)); err != nil || len(converted) != 1 {
			t.Fatalf("%s: upstream does not convert the base link, so nothing below it means anything: %v", scheme, err)
		}
		keys := make([]string, 0)
		for key := range proxyImportQueryFieldLedger.get()[scheme] {
			if _, known := values[key]; known {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			link := base[:strings.Index(base, "#")] + probeSeparator(base) + key + "=" + values[key] + "#N"
			if !upstreamBuildsALoadableNode(link) {
				continue
			}
			probed++
			assertBothDoorsImport(t, scheme+"?"+key, link)
		}
	}
	if probed < 200 {
		t.Fatalf("only %d scheme/key pairs were compared; the fixtures have stopped covering the ledger", probed)
	}

	for _, scheme := range schemes {
		base := bases[scheme]
		link := base[:strings.Index(base, "#")] + probeSeparator(base) + "clash-no-such-key=1#N"
		if !upstreamBuildsALoadableNode(link) {
			t.Fatalf("%s: upstream does not build a loadable node from an unknown query key, "+
				"which contradicts what this test is for", scheme)
		}
		assertBothDoorsImport(t, scheme+" with an unknown key", link)
	}

	t.Logf("compared %d scheme/key pairs against upstream's own converter, plus one unknown key per scheme", probed)
}

func TestThisTreeNeverRefusesAVMessBodyKeyUpstreamIgnores(t *testing.T) {
	body := map[string]any{
		"v": "2", "ps": "N", "add": "e.example", "port": "443",
		"id": "11111111-1111-1111-1111-111111111111", "aid": "0", "scy": "auto",
		"net": "ws", "type": "none", "host": "h.example", "path": "/p", "tls": "tls", "sni": "p.example",
	}
	probes := map[string]any{
		"class":             json.Number("0"),
		"verify_cert":       true,
		"remark":            "R",
		"headerType":        "none",
		"clash-no-such-key": json.Number("1"),
	}
	keys := make([]string, 0, len(probes))
	for key := range probes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		probed := make(map[string]any, len(body)+1)
		for field, value := range body {
			probed[field] = value
		}
		probed[key] = probes[key]
		encoded, err := json.Marshal(probed)
		if err != nil {
			t.Fatalf("%s: encode: %v", key, err)
		}
		link := "vmess://" + base64.StdEncoding.EncodeToString(encoded)
		if !upstreamBuildsALoadableNode(link) {
			t.Fatalf("vmess body with %s: upstream does not build a loadable node, "+
				"which contradicts what this test is for", key)
		}
		assertBothDoorsImport(t, "vmess body with "+key, link)
	}
}

func probeSeparator(link string) string {
	if strings.Contains(link[:strings.Index(link, "#")], "?") {
		return "&"
	}
	return "?"
}

func assertBothDoorsImport(t *testing.T, what, link string) {
	t.Helper()
	box, err := ConvertProxiesForIOS([]byte(link))
	if err != nil {
		t.Errorf("%s: upstream converts this link and ConvertProxiesForIOS refuses it: %v", what, err)
	} else {
		var out struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil || len(out.Proxies) != 1 {
			t.Errorf("%s: ConvertProxiesForIOS produced %d nodes", what, len(out.Proxies))
		}
	}
	inspected, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Errorf("%s: upstream converts this link and InspectProxyPayloadForIOS refuses it: %v", what, err)
		return
	}
	var report struct {
		Proxies []map[string]any `json:"proxies"`
		Skipped []struct {
			Message string `json:"message"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(inspected.Value), &report); err != nil {
		t.Errorf("%s: decode: %v", what, err)
		return
	}
	if len(report.Proxies) != 1 {
		reason := ""
		if len(report.Skipped) > 0 {
			reason = report.Skipped[0].Message
		}
		t.Errorf("%s: upstream converts this link and inspect returned %d nodes: %s", what, len(report.Proxies), reason)
	}
}

func upstreamBuildsALoadableNode(link string) bool {
	converted, err := convert.ConvertsV2Ray([]byte(link))
	if err != nil || len(converted) != 1 {
		return false
	}
	outbound, err := adapter.ParseProxy(converted[0])
	if err != nil {
		return false
	}
	_ = outbound.Close()
	return true
}

func TestANodeKeepsTheNameItsLinkGaveIt(t *testing.T) {
	for _, test := range []struct {
		name string
		link string
		want string
	}{
		{
			name: "a bare closing bracket in the fragment",
			link: "hysteria2://pw@e.example:443#A(B)",
			want: "A(B)",
		},
		{
			name: "an airport suffix the way Shadowrocket exports it",
			link: "hysteria2://pw@e.example:443?insecure=1#\U0001F1EE\U0001F1F314印度-移动/南方联通(hy2)",
			want: "\U0001F1EE\U0001F1F314印度-移动/南方联通(hy2)",
		},
		{
			name: "a name carrying a colon and a slash",
			link: "hysteria2://pw@e.example:443#\U0001F30F自动最优线路(hy2)-网址: new.example.me",
			want: "\U0001F30F自动最优线路(hy2)-网址: new.example.me",
		},
		{
			name: "a full-width closing bracket in the fragment",
			link: "hysteria2://pw@e.example:443#香港（备用）",
			want: "香港（备用）",
		},
		{
			name: "a percent-encoded bracket, which was never at risk",
			link: "hysteria2://pw@e.example:443#A%28B%29",
			want: "A(B)",
		},
		{
			name: "trailing prose punctuation with no opener of its own",
			link: "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080#香港01",
			want: "香港01",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			box, err := ConvertProxiesForIOS([]byte(test.link))
			if err != nil {
				t.Fatalf("the link was refused: %v", err)
			}
			var out struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil || len(out.Proxies) != 1 {
				t.Fatalf("expected one node: %v", err)
			}
			name, _ := out.Proxies[0]["name"].(string)
			if name != test.want {
				t.Fatalf("the node was renamed: got %q, want %q", name, test.want)
			}
		})
	}
}

func TestOnlySomeOutboundsVerifyTheirFingerprint(t *testing.T) {
	required := map[string]map[string]any{
		"trojan":    {"password": "pw"},
		"vmess":     {"uuid": "11111111-1111-1111-1111-111111111111", "alterId": 0, "cipher": "auto"},
		"vless":     {"uuid": "11111111-1111-1111-1111-111111111111"},
		"anytls":    {"password": "pw"},
		"ss":        {"cipher": "chacha20-ietf-poly1305", "password": "pw"},
		"hysteria2": {"password": "pw"},
		"tuic":      {"uuid": "11111111-1111-1111-1111-111111111111", "password": "pw"},
	}
	for proxyType, extra := range required {
		t.Run(proxyType, func(t *testing.T) {
			proxy := map[string]any{"name": "N", "type": proxyType, "server": "e.example", "port": 443}
			for key, value := range extra {
				proxy[key] = value
			}
			proxy["fingerprint"] = "chrome"
			outbound, err := adapter.ParseProxy(proxy)
			if err == nil {
				_ = outbound.Close()
			}
			_, listed := proxyTypesThatVerifyTheirFingerprint.get()[proxyType]
			if listed != (err != nil) {
				t.Fatalf("%s: listed as verifying = %v, but adapter.ParseProxy said %v", proxyType, listed, err)
			}
		})
	}
	for proxyType := range proxyTypesThatVerifyTheirFingerprint.get() {
		if proxyType == "hysteria" {
			continue
		}
		if _, covered := required[proxyType]; !covered {
			t.Fatalf("%s is filtered but never measured, so the list could be wrong without saying so", proxyType)
		}
	}
}

func TestAnUnbuildablePluginLeavesTheNodeWithoutOne(t *testing.T) {
	for _, test := range []struct{ name, link string }{
		{"ss with a plugin name that is not a plugin", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=0#N"},
		{"ss with a plugin mihomo does not have", "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=weird#N"},
		{"trojan with a plugin mihomo does not have", "trojan://pw@e.example:443?plugin=weird#N"},
		{"trojan with an obfs mode that is not websocket", "trojan://pw@e.example:443?plugin=obfs-local;obfs%3Dtls#N"},
		{"snell with a plugin mihomo does not have", "snell://cHNr@e.example:443?plugin=weird&version=4#N"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := readImportReport(t, []byte(test.link))
			if len(report.Proxies) != 1 {
				t.Fatalf("an unbuildable plugin cost the node: %#v", report)
			}
			if plugin, present := report.Proxies[0]["plugin"]; present {
				t.Fatalf("a plugin was set from a name that cannot be built: %v", plugin)
			}
			var named bool
			for _, notice := range report.NotHonoured {
				if strings.Contains(notice.Message, "plugin") {
					named = true
				}
			}
			if !named {
				t.Fatalf("the plugin was dropped without saying so: %#v", report.NotHonoured)
			}
		})
	}

	report := readImportReport(t, []byte("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=obfs-local;obfs%3Dhttp#N"))
	if len(report.Proxies) != 1 || report.Proxies[0]["plugin"] != "obfs" {
		t.Fatalf("a buildable plugin was dropped too: %#v", report.Proxies)
	}
}

func TestAPluginBuildsWhateverCaseItIsWrittenIn(t *testing.T) {
	for _, test := range []struct {
		spec   string
		plugin any
	}{
		{"obfs-local;obfs=http", "obfs"},
		{"OBFS-LOCAL;OBFS=HTTP", "obfs"},
		{"Obfs-Local;Obfs=Http", "obfs"},
		{"obfs-local;OBFS=http", "obfs"},
		{"obfs-local;obfs=tls;obfs-host=cdn.example", "obfs"},
		{"V2RAY-PLUGIN;MODE=WS", "v2ray-plugin"},
		{"v2ray-plugin;mode=websocket", "v2ray-plugin"},
		{"obfs-local;obfs=nonsense", nil},
		{"weird;x=1", nil},
	} {
		t.Run(test.spec, func(t *testing.T) {
			link := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@e.example:1080?plugin=" +
				url.QueryEscape(test.spec) + "#N"
			report := readImportReport(t, []byte(link))
			if len(report.Proxies) != 1 {
				t.Fatalf("the link did not import: %#v", report)
			}
			if got := report.Proxies[0]["plugin"]; got != test.plugin {
				t.Fatalf("plugin = %v, want %v", got, test.plugin)
			}
			outbound, err := adapter.ParseProxy(report.Proxies[0])
			if err != nil {
				t.Fatalf("this importer produced a node the kernel refuses: %v", err)
			}
			_ = outbound.Close()
		})
	}
}
