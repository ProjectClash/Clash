package clash

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/ProjectClash/Clash/common/convert"
)

func TestSecuritySpellingEnablesTLSWhereTLSExists(t *testing.T) {
	for name, tc := range map[string]struct {
		link    string
		wantTLS bool
	}{
		"socks5 security=tls":  {"socks5://dXNlcjpwYXNz@example.com:443?security=tls#Node", true},
		"socks5 security=none": {"socks5://dXNlcjpwYXNz@example.com:443?security=none#Node", false},
		"socks5 tls=1":         {"socks5://dXNlcjpwYXNz@example.com:443?tls=1#Node", true},
		"http security=tls":    {"http://user:pass@example.com:443?security=tls#Node", true},
	} {
		t.Run(name, func(t *testing.T) {
			box, err := ConvertProxiesForIOS([]byte(tc.link))
			if err != nil {
				t.Fatalf("the link was refused: %v", err)
			}
			var out struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil {
				t.Fatalf("import output is not the expected shape: %v\n%s", err, box.Value)
			}
			if len(out.Proxies) != 1 {
				t.Fatalf("expected one proxy, got %d: %s", len(out.Proxies), box.Value)
			}
			tls, _ := out.Proxies[0]["tls"].(bool)
			if tls != tc.wantTLS {
				t.Errorf("tls=%v, want %v — accepting the key and dropping what it says imports the node "+
					"as plaintext and fails at dial time with nothing pointing back at the link:\n%s",
					tls, tc.wantTLS, box.Value)
			}
		})
	}
}

func TestTheSecurityKeyIsNoLongerReportedAsUnsupported(t *testing.T) {
	_, err := ConvertProxiesForIOS([]byte("socks5://dXNlcjpwYXNz@example.com:443?security=tls#Node"))
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "socks5.query.security") {
		t.Fatalf("the field is registered and honoured, and the importer still calls it unsupported: %v", err)
	}
	t.Fatalf("the link was refused for another reason: %v", err)
}

func TestTheAirportUDPSpellingIsHonouredOnShadowsocks(t *testing.T) {
	box, err := ConvertProxiesForIOS([]byte(
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpmYWtlX25vZGVfcGFzc3dvcmQ@1.1.1.1:1080?udp=1#Node"))
	if err != nil {
		t.Fatalf("a link with udp=1 was refused: %v", err)
	}
	var out struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil {
		t.Fatalf("import output is not the expected shape: %v", err)
	}
	if len(out.Proxies) != 1 {
		t.Fatalf("expected one proxy, got %d", len(out.Proxies))
	}
	if udp, _ := out.Proxies[0]["udp"].(bool); !udp {
		t.Errorf("udp=1 was accepted and dropped; the node imports with udp off:\n%s", box.Value)
	}
}

func TestAnUnregisteredQueryKeyReachesTheEditorInsteadOfBeingRefused(t *testing.T) {
	box, err := ConvertProxiesForIOS([]byte(
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpmYWtlX25vZGVfcGFzc3dvcmQ@1.1.1.1:1080?clash-no-such-key=1#Node"))
	if err != nil {
		t.Fatalf("a link carrying one unknown query key was refused whole: %v\n\n"+
			"mihomo reads the keys it knows and ignores the rest, and so does every other client that "+
			"reads these links. A whitelist here makes every future spelling a refusal.", err)
	}
	if !strings.Contains(box.Value, "proxies:") {
		t.Fatalf("the link was accepted and produced nothing usable:\n%s", box.Value)
	}
}

func TestUDPMatchesUpstreamWhateverTheLinkSays(t *testing.T) {
	for name, link := range map[string]string{
		"ss with no udp key": "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@1.1.1.1:1080#N",
		"ss with udp=0":      "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@1.1.1.1:1080?udp=0#N",
		"ss with udp=1":      "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwd2Q@1.1.1.1:1080?udp=1#N",
		"trojan with no key": "trojan://pw@example.com:443#N",
	} {
		t.Run(name, func(t *testing.T) {
			upstream, err := convert.ConvertsV2Ray([]byte(link))
			if err != nil || len(upstream) != 1 {
				t.Skipf("upstream does not convert this shape, so there is nothing to match: %v", err)
			}
			box, err := ConvertProxiesForIOS([]byte(link))
			if err != nil {
				t.Fatalf("this tree refuses a link upstream converts: %v", err)
			}
			var out struct {
				Proxies []map[string]any `yaml:"proxies"`
			}
			if err := yaml.Unmarshal([]byte(box.Value), &out); err != nil {
				t.Fatalf("import output is not the expected shape: %v", err)
			}
			if len(out.Proxies) != 1 {
				t.Fatalf("expected one proxy, got %d", len(out.Proxies))
			}
			theirs, _ := upstream[0]["udp"].(bool)
			ours, _ := out.Proxies[0]["udp"].(bool)
			if theirs != ours {
				t.Errorf("udp: upstream %v, this tree %v — a query key must not change what upstream "+
					"decides unconditionally", theirs, ours)
			}
		})
	}
}
