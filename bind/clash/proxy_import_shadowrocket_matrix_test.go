package clash

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
)

func shadowrocketB64(s string) string    { return base64.StdEncoding.EncodeToString([]byte(s)) }
func shadowrocketB64URL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

const shadowrocketUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
const shadowrocketWGPublicKey = "Z7h2wWmH5JtR4q1QnYp8Yc0v2zQy3Xl9sK6dT8fB1mA="

var shadowrocketMatrixDefects = []struct {
	name   string
	link   string
	expect map[string]string
}{
	{
		name: "ss + v2ray-plugin without mode",
		link: "ss://" + shadowrocketB64("aes-128-gcm:pass") + "@ss.example.com:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws#SS-v2",
		expect: map[string]string{"type": "ss", "plugin": "v2ray-plugin", "plugin-opts.mode": "websocket",
			"plugin-opts.host": "cdn.example.com", "plugin-opts.path": "/ws", "plugin-opts.tls": "true"},
	},
	{
		name: "vmess (Shadowrocket form) obfs=h2",
		link: "vmess://" + shadowrocketB64URL("auto:"+shadowrocketUUID+"@vm.example.com:443") + "?remarks=VM%20H2&obfs=h2&path=/h2&obfsParam=cdn.example.com&tls=1&alterId=0",
		expect: map[string]string{"type": "vmess", "network": "h2", "tls": "true",
			"h2-opts.path": "/h2", "h2-opts.host": "cdn.example.com"},
	},
	{
		name: "vmess (Shadowrocket form) obfs=http",
		link: "vmess://" + shadowrocketB64URL("auto:"+shadowrocketUUID+"@vm.example.com:80") + "?remarks=VM%20HTTP&obfs=http&path=/&obfsParam=cdn.example.com&alterId=0",
		expect: map[string]string{"type": "vmess", "network": "http",
			"http-opts.path": "/", "http-opts.headers.Host": "cdn.example.com"},
	},
	{
		name: "trojan ws with host=",
		link: "trojan://pass@tj.example.com:443?sni=sni.example.com&type=ws&host=cdn.example.com&path=%2Fws#TJ%20WS",
		expect: map[string]string{"type": "trojan", "network": "ws", "ws-opts.path": "/ws",
			"ws-opts.headers.Host": "cdn.example.com"},
	},
	{
		name: "hysteria (Shadowrocket form) obfs=xplus&obfsParam=",
		link: "hysteria://hy.example.com:443?protocol=udp&auth=secret&peer=sni.example.com&insecure=1&upmbps=50&downmbps=100&alpn=h3&obfs=xplus&obfsParam=obfskey#HY1",
		expect: map[string]string{"type": "hysteria", "auth_str": "secret", "obfs": "obfskey",
			"sni": "sni.example.com", "skip-cert-verify": "true"},
	},
	{
		name: "wireguard address=",
		link: "wireguard://" + "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=" + "@wg.example.com:51820?publickey=" + shadowrocketWGPublicKey + "&address=10.0.0.2%2F32&mtu=1420#WG",
		expect: map[string]string{"type": "wireguard", "public-key": shadowrocketWGPublicKey,
			"ip": "10.0.0.2/32", "mtu": "1420", "private-key": "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI="},
	},
}

func TestShadowrocketMatrixDefectsImportAndBuild(t *testing.T) {
	for _, test := range shadowrocketMatrixDefects {
		for _, context := range []string{"singleNode", "subscriptionBody"} {
			t.Run(test.name+"/"+context, func(t *testing.T) {
				report := inspectProxyPayloadReport(t, test.link, context)
				if len(report.Proxies) != 1 {
					t.Fatalf("want one node, got %d; skipped %v", len(report.Proxies), report.Skipped)
				}
				proxy := report.Proxies[0]
				if len(report.NotHonoured) != 0 {
					t.Errorf("fields reported as not honoured: %v", report.NotHonoured)
				}
				for path, want := range test.expect {
					if got := shadowrocketField(proxy, path); got != want {
						t.Errorf("%s = %q, want %q (notHonoured %v)", path, got, want, report.NotHonoured)
					}
				}
				if _, err := adapter.ParseProxy(proxy); err != nil {
					t.Errorf("the imported node does not build: %v\n%v", err, proxy)
				}
			})
		}
	}
}

func shadowrocketField(node map[string]any, path string) string {
	var current any = node
	for _, segment := range strings.Split(path, ".") {
		mapping, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		value, found := mapping[segment]
		if !found {
			for key, candidate := range mapping {
				if strings.EqualFold(key, segment) {
					value, found = candidate, true
					break
				}
			}
		}
		if !found {
			return ""
		}
		current = value
	}
	switch value := current.(type) {
	case nil:
		return ""
	case []any:
		if len(value) == 1 {
			return fmt.Sprint(value[0])
		}
		return fmt.Sprint(value)
	case []string:
		if len(value) == 1 {
			return value[0]
		}
		return fmt.Sprint(value)
	default:
		return fmt.Sprint(value)
	}
}

func TestAPercentEncodedPasswordArrivesByteForByte(t *testing.T) {
	passwords := map[string]string{
		"pa%2Bss%2Fw%3Drd":     "pa+ss/w=rd",
		"p%40ss%3Aw0rd":        "p@ss:w0rd",
		"Pa$$w0rd%21":          "Pa$$w0rd!",
		"%E5%AF%86%E7%A0%810O": "密码0O",
	}
	for encoded, want := range passwords {
		for _, link := range []string{
			"hysteria2://" + encoded + "@hy.example.com:443?sni=sni.example.com#HY2",
			"hy2://" + encoded + "@hy.example.com:443?sni=sni.example.com#HY2",
		} {
			report := inspectProxyPayloadReport(t, link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("%s: want one node, got %d (%v)", link, len(report.Proxies), report.Skipped)
			}
			if got := shadowrocketField(report.Proxies[0], "password"); got != want {
				t.Errorf("%s: password %q, want %q", link, got, want)
			}
		}
		for _, link := range []string{
			"socks5://alice:" + encoded + "@sk.example.com:1080#SOCKS",
			"http://alice:" + encoded + "@hp.example.com:8080#HTTP",
		} {
			report := inspectProxyPayloadReport(t, link, "singleNode")
			if len(report.Proxies) != 1 {
				t.Fatalf("%s: want one node, got %d (%v)", link, len(report.Proxies), report.Skipped)
			}
			if got := shadowrocketField(report.Proxies[0], "password"); got != want {
				t.Errorf("%s: password %q, want %q", link, got, want)
			}
			if got := shadowrocketField(report.Proxies[0], "username"); got != "alice" {
				t.Errorf("%s: username %q, want alice", link, got)
			}
		}
	}
	report := inspectProxyPayloadReport(t, "hysteria2://bob:s%3Acret@hy.example.com:443#HY2", "singleNode")
	if got := shadowrocketField(report.Proxies[0], "password"); got != "bob:s:cret" {
		t.Errorf("userpass auth: password %q, want %q", got, "bob:s:cret")
	}
}

func TestShadowrocketDialectEdges(t *testing.T) {
	report := inspectProxyPayloadReport(t, "trojan://pass@tj.example.com:443?obfs=h2&obfsParam=cdn.example.com&path=/h2#TJ", "singleNode")
	if !strings.Contains(fmt.Sprint(report.NotHonoured), `mihomo's trojan has no "h2" transport`) {
		t.Errorf("trojan obfs=h2 must be said: %v", report.NotHonoured)
	}
	report = inspectProxyPayloadReport(t, "vless://"+shadowrocketUUID+"@vl.example.com:443?type=ws&obfs=h2&host=cdn.example.com&path=/w&security=tls&sni=sni.example.com#VL", "singleNode")
	node := report.Proxies[0]
	if _, stale := node["ws-opts"]; stale || node["network"] != "h2" {
		t.Errorf("obfs=h2 over type=ws must leave one transport: %v", node)
	}
	report = inspectProxyPayloadReport(t, "vmess://"+shadowrocketB64URL("auto:"+shadowrocketUUID+"@vm.example.com:443")+"?obfs=h2&path=/h2&tls=1&peer=sni.example.com&alterId=0", "singleNode")
	if got := shadowrocketField(report.Proxies[0], "h2-opts.host"); got != "" {
		t.Errorf("h2 with no obfsParam writes no host, as a standard type=h2 link does: %q", got)
	}
	if _, err := adapter.ParseProxy(report.Proxies[0]); err != nil {
		t.Errorf("does not build: %v", err)
	}
	report = inspectProxyPayloadReport(t, "wireguard://SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=@wg.example.com:51820?publickey="+shadowrocketWGPublicKey+"&address=10.0.0.2%2F32&presharedkey="+shadowrocketWGPublicKey+"#WG", "singleNode")
	if got := shadowrocketField(report.Proxies[0], "pre-shared-key"); got != shadowrocketWGPublicKey {
		t.Errorf("lowercase presharedkey: %q", got)
	}
}

func TestShadowrocketDialectKeepsTheStandardTransport(t *testing.T) {
	report := inspectProxyPayloadReport(t, "trojan://pw@t.example.com:443?type=grpc&serviceName=svc&obfsParam=foo.example.com&sni=t.example.com#T", "singleNode")
	if got := shadowrocketField(report.Proxies[0], "network"); got != "grpc" {
		t.Errorf("type=grpc with a stray obfsParam must stay grpc, got %q", got)
	}
	if got := shadowrocketField(report.Proxies[0], "grpc-opts.grpc-service-name"); got != "svc" {
		t.Errorf("service name %q", got)
	}
	report = inspectProxyPayloadReport(t, "vless://"+shadowrocketUUID+"@vl.example.com:443?type=ws&path=/p&host=h.example.com&ed=2048&obfs=websocket&security=tls#V", "singleNode")
	if got := shadowrocketField(report.Proxies[0], "ws-opts.max-early-data"); got != "2048" {
		t.Errorf("obfs=websocket over type=ws must keep early data, got %q (%v)", got, report.Proxies[0]["ws-opts"])
	}
	report = inspectProxyPayloadReport(t, "ss://"+shadowrocketB64("aes-128-gcm:pass")+"@ss.example.com:443?obfs=grpc&path=svc#S", "singleNode")
	if !strings.Contains(fmt.Sprint(report.NotHonoured), `no "grpc" transport`) {
		t.Errorf("an obfs the outbound cannot carry must be said: %v", report.NotHonoured)
	}
}
