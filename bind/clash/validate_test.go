package clash

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/dns"
	LC "github.com/ProjectClash/Clash/listener/config"
)

func TestValidateForIOS(t *testing.T) {
	t.Run("carries dhcp and system rather than refusing them", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Addr: "1.1.1.1:53"}, {Net: "dhcp", Addr: "en0"}, {Net: "system"}},
		}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("dhcp/system nameserver refused the config: %v", err)
		}
	})

	t.Run("rejects empty nameserver when DNS enabled", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{Enable: true}}
		err := validateForIOS(cfg, false)
		if err == nil || !strings.Contains(err.Error(), "nameserver must be set") {
			t.Fatalf("expected empty-nameserver rejection, got %v", err)
		}
	})

	t.Run("accepts explicit nameserver", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Net: "", Addr: "8.8.8.8:53"}},
		}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	})

	t.Run("tolerates DNS fragment naming an unroutable proxy (fails closed at runtime)", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Addr: "1.1.1.1:53", ProxyName: "en0"}},
		}}
		if err := validateForIOS(cfg, true); err != nil {
			t.Fatalf("unroutable DNS fragment should be tolerated: %v", err)
		}
	})

	t.Run("allows DNS physical interface fragment outside NetworkExtension", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{
			Enable:     true,
			NameServer: []dns.NameServer{{Addr: "1.1.1.1:53", ProxyName: "en0"}},
		}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("non-NE DNS interface fragment rejected: %v", err)
		}
	})

	t.Run("accepts DNS fragment naming a configured proxy or RULES", func(t *testing.T) {
		for _, proxyName := range []string{"DNS-PROXY", dns.RespectRules} {
			cfg := &config.Config{
				DNS: &config.DNS{
					Enable:     true,
					NameServer: []dns.NameServer{{Addr: "1.1.1.1:53", ProxyName: proxyName}},
				},
				Proxies: map[string]C.Proxy{"DNS-PROXY": nil},
			}
			if err := validateForIOS(cfg, true); err != nil {
				t.Fatalf("DNS proxy fragment %q rejected: %v", proxyName, err)
			}
		}
	})

	t.Run("no resolver slot makes dhcp or system fatal", func(t *testing.T) {
		for _, scheme := range []dns.NameServer{{Net: "dhcp", Addr: "en0"}, {Net: "system"}} {
			setters := map[string]func(*config.DNS){
				"nameserver":              func(c *config.DNS) { c.NameServer = append(c.NameServer, scheme) },
				"fallback":                func(c *config.DNS) { c.Fallback = []dns.NameServer{scheme} },
				"default-nameserver":      func(c *config.DNS) { c.DefaultNameserver = []dns.NameServer{scheme} },
				"proxy-server-nameserver": func(c *config.DNS) { c.ProxyServerNameserver = []dns.NameServer{scheme} },
				"direct-nameserver":       func(c *config.DNS) { c.DirectNameServer = []dns.NameServer{scheme} },
				"nameserver-policy": func(c *config.DNS) {
					c.NameServerPolicy = []dns.Policy{{Domain: "example.com", NameServers: []dns.NameServer{scheme}}}
				},
				"proxy-server-nameserver-policy": func(c *config.DNS) {
					c.ProxyServerPolicy = []dns.Policy{{Domain: "example.com", NameServers: []dns.NameServer{scheme}}}
				},
			}
			for name, set := range setters {
				t.Run(scheme.Net+"/"+name, func(t *testing.T) {
					cfg := &config.Config{DNS: &config.DNS{
						Enable:     true,
						NameServer: []dns.NameServer{{Addr: "1.1.1.1:53"}},
					}}
					set(cfg.DNS)
					if err := validateForIOS(cfg, true); err != nil {
						t.Fatalf("%s resolver in %s refused the config: %v", scheme.Net, name, err)
					}
				})
			}
		}
	})

	t.Run("DNS disabled skips validation", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{Enable: false}}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("disabled DNS should pass: %v", err)
		}
	})

	t.Run("DNS disabled is accepted, as mihomo accepts it", func(t *testing.T) {
		cfg := &config.Config{DNS: &config.DNS{Enable: false}}
		if err := validateForIOS(cfg, true); err != nil {
			t.Fatalf("mihomo accepts dns.enable false and so must this core: %v", err)
		}
	})

	t.Run("route address sets load, because upstream ignores them off Linux", func(t *testing.T) {
		cfg := &config.Config{
			General: &config.General{Inbound: config.Inbound{Tun: LC.Tun{
				RouteAddressSet: []string{"private"},
			}}},
			DNS: &config.DNS{Enable: false},
		}
		if err := validateForIOS(cfg, false); err != nil {
			t.Fatalf("route set must not refuse the configuration: %v", err)
		}
	})
}

func TestValidateRawNetworkExtensionIntentToleratesUnexecutableMetadataRules(t *testing.T) {
	tests := map[string]string{
		"process name":     "rules:\n  - PROCESS-NAME,curl,DIRECT\n",
		"process wildcard": "rules:\n  - PROCESS-PATH-WILDCARD,/private/*,DIRECT\n",
		"uid":              "rules:\n  - UID,501,DIRECT\n",
		"in user":          "rules:\n  - IN-USER,alice,DIRECT\n",
		"signing id":       "rules:\n  - SOURCE-APP-SIGNING-ID,com.example.cli,DIRECT\n",
		"Team id":          "rules:\n  - SOURCE-APP-TEAM-ID,ABCDE12345,DIRECT\n",
		"logic nested":     "rules:\n  - AND,((PROCESS-NAME-REGEX,^curl$),(NETWORK,TCP)),DIRECT\n",
		"sub-rule":         "sub-rules:\n  child:\n    - PROCESS-NAME-WILDCARD,curl*,DIRECT\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("unexecutable metadata rule should be tolerated (no-op), got: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentToleratesHostRouteKnobs(t *testing.T) {
	tolerated := map[string]string{
		"interface-name":     "interface-name: en0\n",
		"routing-mark":       "routing-mark: 233\n",
		"find-process-mode":  "find-process-mode: always\n",
		"tun auto-redirect":  "tun:\n  auto-redirect: true\n",
		"tun iproute2":       "tun:\n  iproute2-table-index: 100\n",
		"tun include-if":     "tun:\n  include-interface: [en0]\n",
		"tun exclude-if":     "tun:\n  exclude-interface: [en1]\n",
		"tun include-uid":    "tun:\n  include-uid: [501]\n",
		"tun exclude-uid":    "tun:\n  exclude-uid: [0]\n",
		"tun include-uid-rg": "tun:\n  include-uid-range: ['1000:2000']\n",
		"tun exclude-dst":    "tun:\n  exclude-dst-port: [443]\n",
		"tun exclude-src":    "tun:\n  exclude-src-port: [53]\n",
		"tun package":        "tun:\n  include-package: [com.example.app]\n",
		"tun android-user":   "tun:\n  include-android-user: [0]\n",
		"tun mac":            "tun:\n  include-mac-address: ['00:11:22:33:44:55']\n",
	}
	for name, content := range tolerated {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("host-route knob should be tolerated (stripped later), got: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentDoesNotMatchOrdinaryPayload(t *testing.T) {
	content := "rules:\n  - DOMAIN,process-name,DIRECT\n  - DOMAIN-SUFFIX,uid.example,DIRECT\n"
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawNetworkExtensionIntent(raw); err != nil {
		t.Fatalf("ordinary domain payload was mistaken for metadata rule: %v", err)
	}
}

func TestValidateRawNetworkExtensionIntentToleratesOutboundEgressOverrides(t *testing.T) {
	for name, content := range map[string]string{
		"proxy interface": `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0}
`,
		"proxy routing mark": `
proxies:
  - {name: node, type: socks5, server: 127.0.0.1, port: 1080, routing-mark: 233}
`,
		"group ignored field": `
proxy-groups:
  - {name: group, type: select, proxies: [DIRECT], interface-name: en0}
`,
		"provider override": `
proxy-providers:
  nodes:
    type: http
    url: https://example.com/proxies.yaml
    override: {routing-mark: 233}
`,
		"inline provider payload": `
proxy-providers:
  nodes:
    type: inline
    payload:
      - {name: node, type: socks5, server: 127.0.0.1, port: 1080, interface-name: en0}
`,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("outbound egress override should be tolerated (stripped), got: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentToleratesOutboundDNSInterfaceFragments(t *testing.T) {
	for name, content := range map[string]string{
		"top-level wireguard": `
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#en0"]
`,
		"inline provider masque": `
proxy-providers:
  nodes:
    type: inline
    payload:
      - name: tunnel
        type: masque
        remote-dns-resolve: true
        dns: ["tls://dns.example#pdp_ip0"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("an outbound DNS interface fragment is inert upstream, not fatal, "+
					"so the whole configuration must not be refused for it: %v", err)
			}
		})
	}
}

func TestValidateRawNetworkExtensionIntentToleratesIgnoredOutboundDNSProxyFragment(t *testing.T) {
	content := `
proxy-groups:
  - {name: DNS PROXY, type: select, proxies: [DIRECT]}
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#DNS%20PROXY"]
`
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRawNetworkExtensionIntent(raw); err != nil {
		t.Fatalf("an outbound DNS proxy fragment is inert upstream, not fatal: %v", err)
	}
}

func TestValidateRawNetworkExtensionIntentAllowsInactiveOrParameterizedOutboundDNS(t *testing.T) {
	for name, content := range map[string]string{
		"remote resolution disabled": `
proxies:
  - name: tunnel
    type: wireguard
    remote-dns-resolve: false
    dns: ["https://dns.example/dns-query#en0"]
`,
		"fragment contains parameters only": `
proxies:
  - name: tunnel
    type: masque
    remote-dns-resolve: true
    dns: ["https://dns.example/dns-query#h3=true&skip-cert-verify=false"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRawNetworkExtensionIntent(raw); err != nil {
				t.Fatalf("valid nested DNS configuration rejected: %v", err)
			}
		})
	}
}

func TestDNSFragmentProxyNameMatchesMihomoURIParsing(t *testing.T) {
	for input, want := range map[string]string{
		"https://dns.example/dns-query#DNS%20PROXY&h3=true": "DNS PROXY",
		"quic://dns.example#h3=true":                        "",
		"tls://dns.example#first&skip-cert-verify=true":     "first",
	} {
		if got := dnsFragmentProxyName(input); got != want {
			t.Fatalf("dnsFragmentProxyName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOutboundEgressOverrideFieldsReportsEveryPresentField(t *testing.T) {
	mapping := map[string]any{"interface-name": "en0", "routing-mark": 233}
	if got, want := outboundEgressOverrideFields(mapping), []string{"interface-name", "routing-mark"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound egress override fields = %v, want %v", got, want)
	}
}
