package config

import (
	"strings"
	"testing"
)

func TestClashRoutingParses(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("x-clash-udp-unsupported: reject\nx-clash-every-mode-rules:\n  - DOMAIN-SUFFIX,ads.example,REJECT\n" +
		"x-clash-stun-response-ip: 1.1.1.1\nx-clash-stun-response-ipv6: \"::1\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClashRouting.UDPUnsupported != "REJECT" || len(cfg.ClashRouting.EveryModeRules) != 1 ||
		cfg.ClashRouting.EveryModeRules[0].Payload() != "ads.example" ||
		cfg.ClashRouting.STUNResponseIPv4.String() != "1.1.1.1" || cfg.ClashRouting.STUNResponseIPv6.String() != "::1" {
		t.Fatalf("parsed %+v", cfg.ClashRouting)
	}
}

func TestClashRoutingRefusesWhatItCannotDo(t *testing.T) {
	for doc, want := range map[string]string{
		"x-clash-udp-unsupported: proxy\n":                                "x-clash-udp-unsupported",
		"x-clash-every-mode-rules:\n  - DOMAIN,a.example,NO-SUCH-PROXY\n": "x-clash-every-mode-rules",
	} {
		raw, err := UnmarshalRawConfig([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRawConfig(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", doc, err)
		}
	}
}

func TestBlockQUICParses(t *testing.T) {
	for value, want := range map[string]string{"all-proxy": "all-proxy", "ALL": "all", "off": "", "always-allow": "", "per-policy": "", "": ""} {
		raw, err := UnmarshalRawConfig([]byte("x-clash-block-quic: \"" + value + "\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := ParseRawConfig(raw)
		if err != nil || cfg.ClashRouting.BlockQUIC != want {
			t.Errorf("%q: %q (%v), want %q", value, cfg.ClashRouting.BlockQUIC, err, want)
		}
	}
	raw, _ := UnmarshalRawConfig([]byte("x-clash-block-quic: proxies\n"))
	if _, err := ParseRawConfig(raw); err == nil || !strings.Contains(err.Error(), "x-clash-block-quic") {
		t.Errorf("an unknown value: %v", err)
	}
}

func TestProxyHostsParse(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`x-clash-proxy-hosts:
  api.example: 2606:4700:4700::1001
  "+.cdn.example": [192.0.2.1, 192.0.2.2]
  alias.example: edge.example
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil || cfg.ClashRouting.ProxyHosts == nil {
		t.Fatalf("parsed %v (%v)", cfg.ClashRouting.ProxyHosts, err)
	}
	hosts := cfg.ClashRouting.ProxyHosts
	if ips, name, ok := hosts.SearchProxyHost("api.example"); !ok || name != "" || len(ips) != 1 || ips[0].String() != "2606:4700:4700::1001" {
		t.Errorf("api.example: %v %q %v", ips, name, ok)
	}
	if ips, _, ok := hosts.SearchProxyHost("img.cdn.example"); !ok || len(ips) != 2 {
		t.Errorf("img.cdn.example: %v %v", ips, ok)
	}
	if ips, name, ok := hosts.SearchProxyHost("alias.example"); !ok || len(ips) != 0 || name != "edge.example" {
		t.Errorf("alias.example: %v %q %v", ips, name, ok)
	}
	if _, _, ok := hosts.SearchProxyHost("other.example"); ok {
		t.Error("a host with no entry matched")
	}
	if _, _, ok := hosts.SearchProxyHost("localhost"); ok {
		t.Error("hosts' own localhost entry reached proxy-hosts")
	}

	raw, _ = UnmarshalRawConfig([]byte("hosts:\n  api.example: 192.0.2.9\n"))
	if cfg, err := ParseRawConfig(raw); err != nil || cfg.ClashRouting.ProxyHosts != nil {
		t.Errorf("without the key: %v (%v)", cfg.ClashRouting.ProxyHosts, err)
	}
	raw, _ = UnmarshalRawConfig([]byte("x-clash-proxy-hosts:\n  api.example: {a: b}\n"))
	if _, err := ParseRawConfig(raw); err == nil || !strings.Contains(err.Error(), "x-clash-proxy-hosts[api.example]") {
		t.Errorf("a value that is not an address or name: %v", err)
	}
}
