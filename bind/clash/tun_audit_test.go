package clash

import (
	"fmt"
	"slices"
	"testing"

	LC "github.com/ProjectClash/Clash/listener/config"
)

func TestEveryTunFieldDoesWhatTheCatalogSays(t *testing.T) {
	const honouredDocument = `
ipv6: true
tun:
  enable: true
  strict-route: true
  endpoint-independent-nat: true
  udp-timeout: 123
  icmp-timeout: 45
  route-address: [10.9.0.0/16]
  route-exclude-address: [10.8.0.0/16]
  inet4-route-address: [10.7.0.0/16]
  inet6-route-address: ["fd00::/8"]
  inet4-route-exclude-address: [10.6.0.0/16]
  inet6-route-exclude-address: ["fd01::/8"]
  loopback-address: [10.5.0.1]
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, honouredDocument)
	finalizeConfigForIOS(ours, true)
	up, got := mihomo.General.Tun, ours.General.Tun

	for name, pair := range map[string][2]any{
		"strict-route":                {up.StrictRoute, got.StrictRoute},
		"endpoint-independent-nat":    {up.EndpointIndependentNat, got.EndpointIndependentNat},
		"udp-timeout":                 {up.UDPTimeout, got.UDPTimeout},
		"icmp-timeout":                {up.ICMPTimeout, got.ICMPTimeout},
		"route-address":               {up.RouteAddress, got.RouteAddress},
		"route-exclude-address":       {up.RouteExcludeAddress, got.RouteExcludeAddress},
		"inet4-route-address":         {up.Inet4RouteAddress, got.Inet4RouteAddress},
		"inet6-route-address":         {up.Inet6RouteAddress, got.Inet6RouteAddress},
		"inet4-route-exclude-address": {up.Inet4RouteExcludeAddress, got.Inet4RouteExcludeAddress},
		"inet6-route-exclude-address": {up.Inet6RouteExcludeAddress, got.Inet6RouteExcludeAddress},
		"loopback-address":            {up.LoopbackAddress, got.LoopbackAddress},
		"inet6-address":               {up.Inet6Address, got.Inet6Address},
	} {
		if fmt.Sprint(pair[0]) != fmt.Sprint(pair[1]) {
			t.Errorf("tun.%s is catalogued keep: mihomo %v, ours %v", name, pair[0], pair[1])
		}
	}
}

func TestEveryForcedTunFieldIsStillForced(t *testing.T) {
	const document = `
tun:
  enable: true
  device: my-utun
  mtu: 1400
  auto-route: true
  auto-detect-interface: true
  gso: true
  gso-max-size: 65536
  recvmsgx: true
  sendmsgx: true
  disable-icmp-forwarding: false
  dns-hijack: [1.1.1.1:53]
  include-interface: [en9]
  exclude-interface: [en8]
  include-uid: [501]
  exclude-uid: [0]
  include-uid-range: ["1000:2000"]
  exclude-uid-range: ["3000:4000"]
  exclude-src-port: [5353]
  exclude-dst-port: [5354]
  exclude-src-port-range: ["100:200"]
  exclude-dst-port-range: ["300:400"]
  include-mac-address: ["00:11:22:33:44:55"]
  exclude-mac-address: ["66:77:88:99:aa:bb"]
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	if mihomo.General.Tun.Device != "my-utun" || len(mihomo.General.Tun.IncludeUID) == 0 {
		t.Fatalf("fixture is wrong, not the code: upstream did not keep the values under test")
	}
	finalizeConfigForIOS(ours, true)
	got := ours.General.Tun

	if got.Device != packetFlowBridgeDevice {
		t.Errorf("tun.device = %q; the extension has an NEPacketTunnelFlow, not a utun", got.Device)
	}
	if got.MTU != uint32(effectiveTunMTU()) {
		t.Errorf("tun.mtu = %d; core and Swift must carry one number", got.MTU)
	}
	if got.AutoRoute || got.AutoDetectInterface {
		t.Error("tun.auto-route/auto-detect-interface survived; Swift installs the routes")
	}
	if got.GSO || got.GSOMaxSize != 0 || got.RecvMsgX || got.SendMsgX {
		t.Error("a utun-only socket feature survived onto the SOCK_DGRAM bridge")
	}
	if !got.DisableICMPForwarding {
		t.Error("ICMP forwarding survived; it needs a raw socket no unprivileged Apple process has")
	}
	if !slices.Equal(got.DNSHijack, []string{"1.1.1.1:53"}) {
		t.Errorf("tun.dns-hijack = %v; want exactly what was written", got.DNSHijack)
	}
	for name, value := range map[string]int{
		"include-interface":      len(got.IncludeInterface),
		"exclude-interface":      len(got.ExcludeInterface),
		"include-uid":            len(got.IncludeUID),
		"exclude-uid":            len(got.ExcludeUID),
		"include-uid-range":      len(got.IncludeUIDRange),
		"exclude-uid-range":      len(got.ExcludeUIDRange),
		"exclude-src-port":       len(got.ExcludeSrcPort),
		"exclude-dst-port":       len(got.ExcludeDstPort),
		"exclude-src-port-range": len(got.ExcludeSrcPortRange),
		"exclude-dst-port-range": len(got.ExcludeDstPortRange),
		"include-mac-address":    len(got.IncludeMACAddress),
		"exclude-mac-address":    len(got.ExcludeMACAddress),
	} {
		if value == 0 {
			t.Errorf("tun.%s was removed; only Linux code reads it, so it reaches upstream as written", name)
		}
	}
}

func TestEveryTunInterventionReachesTheDeviationReport(t *testing.T) {
	const document = `
tun:
  enable: false
  device: my-utun
  mtu: 1400
  auto-route: true
  auto-detect-interface: true
  gso: true
  gso-max-size: 65536
  recvmsgx: true
  sendmsgx: true
  disable-icmp-forwarding: false
  dns-hijack: [1.1.1.1:53]
  include-interface: [en9]
  exclude-interface: [en8]
  include-uid: [501]
  exclude-uid: [0]
  include-uid-range: ["1000:2000"]
  exclude-uid-range: ["3000:4000"]
  exclude-src-port: [5353]
  exclude-dst-port: [5354]
  exclude-src-port-range: ["100:200"]
  exclude-dst-port-range: ["300:400"]
  include-mac-address: ["00:11:22:33:44:55"]
  exclude-mac-address: ["66:77:88:99:aa:bb"]
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, currentRuntimePolicy(true))
	if err != nil {
		t.Fatalf("collect deviations: %v", err)
	}
	reported := map[string]configDeviation{}
	for _, deviation := range deviations {
		reported[deviation.Field] = deviation
	}
	for _, field := range []string{
		"tun.enable", "tun.device", "tun.mtu", "tun.auto-route", "tun.auto-detect-interface",
		"tun.gso", "tun.gso-max-size", "tun.recvmsgx", "tun.sendmsgx",
		"tun.disable-icmp-forwarding",
		"tun.include-interface", "tun.exclude-interface", "tun.include-uid", "tun.exclude-uid",
		"tun.include-uid-range", "tun.exclude-uid-range", "tun.exclude-src-port",
		"tun.exclude-dst-port", "tun.exclude-src-port-range", "tun.exclude-dst-port-range",
		"tun.include-mac-address", "tun.exclude-mac-address",
	} {
		deviation, ok := reported[field]
		if !ok {
			t.Errorf("%s is changed and says nothing at runtime", field)
			continue
		}
		if deviation.Given == "" {
			t.Errorf("%s reports no given value; a reader cannot match the row to their file", field)
		}
	}

	quiet, err := collectConfigDeviations(`
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, currentRuntimePolicy(true))
	if err != nil {
		t.Fatalf("collect deviations for the quiet configuration: %v", err)
	}
	for _, deviation := range quiet {
		if deviation.Field == "tun.stack" && !deviation.Written {
			continue
		}
		if len(deviation.Field) > 4 && deviation.Field[:4] == "tun." {
			t.Errorf("a configuration with no tun block was told about %s", deviation.Field)
		}
	}
}

func TestDNSHijackRunsExactlyAsWritten(t *testing.T) {
	restoreRuntimeProfileForTest(t)
	parse := func(tunBlock string) LC.Tun {
		t.Helper()
		cfg, err := parseConfigForIOS("mode: rule\ntun:\n  enable: true\n"+tunBlock+"proxies: []\nrules:\n  - MATCH,DIRECT\n", true)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		finalizeConfigForIOS(cfg, true)
		return cfg.General.Tun
	}
	for block, want := range map[string][]string{
		"":                                   {"0.0.0.0:53"},
		"  dns-hijack: [\"tcp://any:53\"]\n": {"tcp://any:53"},
		"  dns-hijack: [\"1.1.1.1:53\"]\n":   {"1.1.1.1:53"},
		"  dns-hijack: []\n":                 {},
	} {
		got := parse(block)
		if !slices.Equal(got.DNSHijack, want) && !(len(want) == 0 && len(got.DNSHijack) == 0) {
			t.Errorf("%q: dns-hijack = %v, want %v", block, got.DNSHijack, want)
		}
	}
}
