package clash

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"golang.org/x/crypto/ssh"
)

func srQueryValue(s string) string {
	const allowed = "-._~!$'()*,;:@/"
	var b strings.Builder
	for _, r := range []byte(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.IndexByte(allowed, r) >= 0:
			b.WriteByte(r)
		default:
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}

const srUUID = "5d1c3d8f-77b7-45c7-98c7-6fa54d37766e"

var shadowrocketExportDefects = []struct {
	name   string
	link   string
	expect map[string]string
}{
	{"ss 2022 key with = in the whole-base64 form",
		"ss://" + shadowrocketB64("2022-blake3-aes-128-gcm:"+shadowrocketB64("0123456789abcdef")+"@ss.example.com:8388") + "#SS22",
		map[string]string{"type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": shadowrocketB64("0123456789abcdef"), "server": "ss.example.com", "port": "8388"}},
	{"ss native websocket",
		"ss://" + shadowrocketB64("aes-128-gcm:pass@ss.example.com:80") + "?obfs=websocket&obfsParam=cdn.example.com&path=/ws#SS%20ws",
		map[string]string{"type": "ss", "plugin": "v2ray-plugin", "plugin-opts.mode": "websocket", "plugin-opts.host": "cdn.example.com", "plugin-opts.path": "/ws"}},
	{"ss native websocket + tls",
		"ss://" + shadowrocketB64("aes-128-gcm:pass@ss.example.com:443") + "?obfs=websocket&obfsParam=cdn.example.com&path=/ws&tls=1&sni=cdn.example.com&allowInsecure=1#SS%20wss",
		map[string]string{"type": "ss", "plugin": "v2ray-plugin", "plugin-opts.mode": "websocket", "plugin-opts.tls": "true", "plugin-opts.host": "cdn.example.com", "plugin-opts.path": "/ws"}},
	{"ss obfs=wss",
		"ss://" + shadowrocketB64("aes-128-gcm:pass@ss.example.com:443") + "?obfs=wss&obfsParam=cdn.example.com&path=/ws#SS%20obfs=wss",
		map[string]string{"type": "ss", "plugin": "v2ray-plugin", "plugin-opts.tls": "true", "plugin-opts.path": "/ws"}},
	{"ss obfs=httpupgrade",
		"ss://" + shadowrocketB64("aes-128-gcm:pass@ss.example.com:80") + "?obfs=httpupgrade&obfsParam=cdn.example.com&path=/up#SS%20upgrade",
		map[string]string{"type": "ss", "plugin": "v2ray-plugin", "plugin-opts.v2ray-http-upgrade": "true", "plugin-opts.path": "/up"}},
	{"ss uot",
		"ss://" + shadowrocketB64("aes-128-gcm:pass@ss.example.com:8388") + "?uot=1&tfo=1&udp=1#SS%20uot",
		map[string]string{"type": "ss", "udp-over-tcp": "true", "tfo": "true"}},
	{"vmess httpupgrade",
		"vmess://" + shadowrocketB64("auto:"+srUUID+"@vm.example.com:443") + "?remarks=" + srQueryValue("VM UP") + "&obfs=httpupgrade&obfsParam=cdn.example.com&path=/up&tls=1&alterId=0",
		map[string]string{"type": "vmess", "network": "ws", "ws-opts.v2ray-http-upgrade": "true", "ws-opts.path": "/up"}},
	{"vless httpupgrade",
		"vless://" + shadowrocketB64("none:"+srUUID+"@vl.example.com:443") + "?remarks=" + srQueryValue("VL UP") + "&obfs=httpupgrade&obfsParam=cdn.example.com&path=/up&tls=1",
		map[string]string{"type": "vless", "network": "ws", "ws-opts.v2ray-http-upgrade": "true"}},
	{"vless xhttp",
		"vless://" + shadowrocketB64("none:"+srUUID+"@vl.example.com:443") + "?remarks=" + srQueryValue("VL xhttp") + "&obfs=xhttp&mode=auto&obfsParam=cdn.example.com&path=/x&tls=1&peer=sni.example.com",
		map[string]string{"type": "vless", "network": "xhttp", "xhttp-opts.path": "/x"}},
	{"trojan httpupgrade",
		"trojan://pass@tj.example.com:443?peer=sni.example.com&obfs=httpupgrade&obfsParam=cdn.example.com&path=/up#TJ%20UP",
		map[string]string{"type": "trojan", "network": "ws", "ws-opts.v2ray-http-upgrade": "true", "ws-opts.path": "/up"}},
	{"trojan-go shadowsocks layer",
		"trojan://pass@tj.example.com:443?peer=sni.example.com&proto=shadowsocks&protoParam=" + srQueryValue("aes-128-gcm:sspass") + "#TJ-GO%20SS",
		map[string]string{"type": "trojan", "ss-opts.enabled": "true", "ss-opts.method": "aes-128-gcm", "ss-opts.password": "sspass"}},
	{"tuic v4 token",
		"tuic://:token123@tuic.example.com:443?sni=sni.example.com&alpn=h3#TUIC%20v4",
		map[string]string{"type": "tuic", "token": "token123"}},
	{"https proxy, panel form: name inside the base64",
		"https://" + shadowrocketB64(srUUID+":"+srUUID+"@hs.example.com:443/#🇭🇰 香港 01"),
		map[string]string{"type": "http", "tls": "true", "username": srUUID, "password": srUUID, "name": "🇭🇰 香港 01"}},
	{"https proxy, panel form: base64 containing /",
		"https://" + shadowrocketB64(srUUID+":x???@hs.example.com:443/#🇭🇰 香港 02"),
		map[string]string{"type": "http", "tls": "true", "password": "x???", "name": "🇭🇰 香港 02"}},
}

func TestShadowrocketRealExportsImportAndBuild(t *testing.T) {
	for _, test := range shadowrocketExportDefects {
		for _, context := range []string{"singleNode", "subscriptionBody"} {
			t.Run(test.name+"/"+context, func(t *testing.T) {
				report := inspectProxyPayloadReport(t, test.link, context)
				if len(report.Proxies) != 1 {
					t.Fatalf("want one node, got %d; skipped %v", len(report.Proxies), report.Skipped)
				}
				if len(report.NotHonoured) != 0 {
					t.Errorf("fields reported as not honoured: %v", report.NotHonoured)
				}
				proxy := report.Proxies[0]
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

func TestShadowrocketSSHKeyArrivesAsTheKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", []byte("phrase"))
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(block))
	link := "ssh://user:@ssh.example.com:2222?pk=" + srQueryValue(shadowrocketB64(key)) + "&pp=phrase#SSH%20key"
	for _, context := range []string{"singleNode", "subscriptionBody"} {
		report := inspectProxyPayloadReport(t, link, context)
		if len(report.Proxies) != 1 || len(report.NotHonoured) != 0 {
			t.Fatalf("%s: proxies %d, skipped %v, notHonoured %v", context, len(report.Proxies), report.Skipped, report.NotHonoured)
		}
		proxy := report.Proxies[0]
		if got := shadowrocketField(proxy, "private-key"); got != key {
			t.Fatalf("%s: private-key = %q, want the decoded key", context, got)
		}
		if _, err := adapter.ParseProxy(proxy); err != nil {
			t.Fatalf("%s: the imported node does not build: %v", context, err)
		}
	}
}

func TestSurgeWebsocketLineImports(t *testing.T) {
	body := "[Proxy]\n" +
		"VM = vmess, vm.example.com, 443, username=" + srUUID + ", ws=true, ws-path=/ws, ws-headers=Host:cdn.example.com|User-Agent:x, tls=true\n" +
		"TJ = trojan, tj.example.com, 443, password=pass, sni=sni.example.com, ws=true, ws-path=/t\n"
	report := inspectProxyPayloadReport(t, body, "subscriptionBody")
	if len(report.Proxies) != 2 || len(report.NotHonoured) != 0 {
		t.Fatalf("proxies %d, skipped %v, notHonoured %v", len(report.Proxies), report.Skipped, report.NotHonoured)
	}
	want := []map[string]string{
		{"type": "vmess", "network": "ws", "tls": "true", "ws-opts.path": "/ws", "ws-opts.headers.Host": "cdn.example.com", "ws-opts.headers.User-Agent": "x"},
		{"type": "trojan", "network": "ws", "ws-opts.path": "/t", "sni": "sni.example.com"},
	}
	for index, proxy := range report.Proxies {
		for path, value := range want[index] {
			if got := shadowrocketField(proxy, path); got != value {
				t.Errorf("%d %s = %q, want %q", index, path, got, value)
			}
		}
		if _, err := adapter.ParseProxy(proxy); err != nil {
			t.Errorf("%d does not build: %v", index, err)
		}
	}
}

func TestShadowrocketExportsReview3(t *testing.T) {
	t.Run("trojan-go ss layer keeps the exporter's websocket", func(t *testing.T) {
		link := "trojan://pw@tj.example.com:443?proto=shadowsocks&protoParam=aes-128-gcm:k&obfsParam=cdn.example.com&path=/ws#t1"
		report := inspectProxyPayloadReport(t, link, "singleNode")
		if len(report.Proxies) != 1 {
			t.Fatalf("skipped %v", report.Skipped)
		}
		proxy := report.Proxies[0]
		for path, want := range map[string]string{"network": "ws", "ws-opts.path": "/ws", "ws-opts.headers.Host": "cdn.example.com", "ss-opts.method": "aes-128-gcm"} {
			if got := shadowrocketField(proxy, path); got != want {
				t.Errorf("%s = %q, want %q", path, got, want)
			}
		}
		if _, err := adapter.ParseProxy(proxy); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ss port range with a SIP003 plugin still imports", func(t *testing.T) {
		link := "ss://" + shadowrocketB64("aes-128-gcm:pw@ss.example.com:1000-2000") + "?plugin=obfs-local;obfs=http;obfs-host=x.example.com#n1"
		report := inspectProxyPayloadReport(t, link, "singleNode")
		if len(report.Proxies) != 1 {
			t.Fatalf("skipped %v", report.Skipped)
		}
		proxy := report.Proxies[0]
		if shadowrocketField(proxy, "port") != "1000" || shadowrocketField(proxy, "plugin") != "obfs" {
			t.Fatalf("got %v", proxy)
		}
	})
	t.Run("ss TLS keys off the websocket path are named", func(t *testing.T) {
		for _, query := range []string{
			"obfs=tls&obfsParam=x.example.com&sni=y.example.com&allowInsecure=1",
			"obfs=http&obfsParam=x.example.com&tls=1",
			"plugin=obfs-local%3Bobfs%3Dhttp&tls=1",
			"obfs=websocket&obfsParam=x.example.com&tls=1&sni=y.example.com",
		} {
			link := "ss://" + shadowrocketB64("aes-128-gcm:pw@ss.example.com:443") + "?" + query + "#n"
			report := inspectProxyPayloadReport(t, link, "subscriptionBody")
			if len(report.Proxies) != 1 || len(report.NotHonoured) == 0 {
				t.Errorf("%s: proxies %d, notHonoured %v", query, len(report.Proxies), report.NotHonoured)
			}
		}
	})
	t.Run("surge vmess-aead=false is refused, true is not", func(t *testing.T) {
		body := "[Proxy]\nA = vmess, vm.example.com, 443, username=" + srUUID + ", vmess-aead=false\nB = vmess, vm.example.com, 443, username=" + srUUID + ", vmess-aead=true\n"
		report := inspectProxyPayloadReport(t, body, "subscriptionBody")
		if len(report.Proxies) != 1 || len(report.Skipped) != 1 {
			t.Fatalf("proxies %d skipped %v", len(report.Proxies), report.Skipped)
		}
	})
	t.Run("inner query is judged and inner title decoded", func(t *testing.T) {
		link := "https://" + shadowrocketB64("u:p@hs.example.com:443/?bogus=1#%E9%A6%99%E6%B8%AF%2001")
		report := inspectProxyPayloadReport(t, link, "subscriptionBody")
		if len(report.Proxies) != 1 {
			t.Fatalf("skipped %v", report.Skipped)
		}
		if got := shadowrocketField(report.Proxies[0], "name"); got != "香港 01" {
			t.Errorf("name = %q", got)
		}
		if len(report.NotHonoured) == 0 {
			t.Errorf("inner bogus key passed silently")
		}
	})
}
